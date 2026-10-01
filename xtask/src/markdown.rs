use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

use anyhow::{Context, Result};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd, html};
use sha2::{Digest, Sha256};
use shared::{Heading, PostContent, normalize};

struct Formula<'a> {
    tex: &'a str,
    display: bool,
    offset: usize,
}

// Extract formulas before Markdown block parsing: a TeX row containing '='
// must not turn the preceding matrix into a setext heading.
fn extract_math<'a>(source: &'a str, options: Options, prefix: &str) -> (String, Vec<Formula<'a>>) {
    let mut excluded = Vec::new();
    for (event, range) in Parser::new_ext(source, options).into_offset_iter() {
        if let Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) = &event
            && !dest_url.is_empty()
        {
            excluded.extend(
                source
                    .match_indices(dest_url.as_ref())
                    .map(|(start, _)| start..start + dest_url.len()),
            );
        }
        if matches!(
            event,
            Event::Code(_)
                | Event::Html(_)
                | Event::InlineHtml(_)
                | Event::Start(Tag::CodeBlock(_))
        ) {
            excluded.push(range);
        }
    }
    excluded.sort_by_key(|range| range.start);
    let bytes = source.as_bytes();
    let mut prepared = String::new();
    let mut formulas = Vec::new();
    let mut copied = 0;
    let mut cursor = 0;
    let mut excluded_cursor = 0;
    while cursor < bytes.len() {
        while excluded
            .get(excluded_cursor)
            .is_some_and(|range| range.end <= cursor)
        {
            excluded_cursor += 1;
        }
        if let Some(range) = excluded
            .get(excluded_cursor)
            .filter(|range| range.contains(&cursor))
        {
            cursor = range.end;
            continue;
        }
        let escaped = source[..cursor]
            .bytes()
            .rev()
            .take_while(|b| *b == b'\\')
            .count()
            % 2
            == 1;
        let (opening, closing, display) = if !escaped && bytes[cursor] == b'$' {
            if bytes.get(cursor + 1) == Some(&b'$') {
                ("$$", "$$", true)
            } else {
                ("$", "$", false)
            }
        } else if !escaped && source[cursor..].starts_with("\\(") {
            ("\\(", "\\)", false)
        } else if !escaped && source[cursor..].starts_with("\\[") {
            ("\\[", "\\]", true)
        } else {
            cursor += source[cursor..].chars().next().unwrap().len_utf8();
            continue;
        };
        let start = cursor + opening.len();
        let mut end = start;
        let mut depth = 0usize;
        let mut nested_close = None;
        let mut close = None;
        while end < bytes.len() {
            if !display && source[end..].starts_with("\n\n") {
                break;
            }
            if source[end..].starts_with(closing) {
                if depth == 0 {
                    close = Some(end);
                    break;
                }
                nested_close.get_or_insert(end);
            }
            match bytes[end] {
                b'\\' => {
                    if source[end..].starts_with("\\verb") {
                        let mut content = end + 5;
                        if bytes.get(content) == Some(&b'*') {
                            content += 1;
                        }
                        if let Some(delimiter) = source[content..].chars().next() {
                            content += delimiter.len_utf8();
                            if let Some(length) = source[content..].find(delimiter) {
                                end = content + length + delimiter.len_utf8();
                                continue;
                            }
                        }
                    }
                    end += 1;
                    if end < bytes.len() {
                        end += source[end..].chars().next().unwrap().len_utf8();
                    }
                    continue;
                }
                b'%' => {
                    end = source[end..]
                        .find('\n')
                        .map_or(bytes.len(), |length| end + length);
                    continue;
                }
                b'{' => depth += 1,
                b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
            end += source[end..].chars().next().unwrap().len_utf8();
        }
        if let Some(end) = close.or(nested_close) {
            prepared.push_str(&source[copied..cursor]);
            prepared.push_str(&format!("{prefix}{}END", formulas.len()));
            formulas.push(Formula {
                tex: &source[start..end],
                display,
                offset: start,
            });
            cursor = end + closing.len();
            copied = cursor;
        } else {
            cursor = start;
        }
    }
    prepared.push_str(&source[copied..]);
    (prepared, formulas)
}

pub struct RenderedMarkdown {
    pub content: PostContent,
    pub text: String,
    pub math_fonts: BTreeSet<String>,
    pub has_math: bool,
}

pub use shared::escape_html as escape;

fn task_label(events: &[Event<'_>]) -> String {
    let mut label = String::new();
    for event in events {
        match event {
            Event::End(TagEnd::Paragraph | TagEnd::Item) | Event::Start(Tag::List(_)) => break,
            Event::Text(value) | Event::Code(value) => label.push_str(value),
            Event::SoftBreak | Event::HardBreak => label.push(' '),
            _ => {}
        }
    }
    if label.trim().is_empty() {
        "Task".into()
    } else {
        label.trim().to_owned()
    }
}

fn heading_id(text: &str, used: &mut HashSet<String>) -> String {
    let mut base = String::new();
    for character in normalize(text).chars() {
        if character.is_alphanumeric() {
            base.push(character);
        } else if !base.ends_with('-') && !base.is_empty() {
            base.push('-');
        }
    }
    base = base.trim_end_matches('-').to_owned();
    if base.is_empty() {
        base = "section".into();
    }
    let mut id = base.clone();
    let mut suffix = 2;
    while !used.insert(id.clone()) {
        id = format!("{base}-{suffix}");
        suffix += 1;
    }
    id
}

fn code_block(language: &str, code: &str) -> Result<String> {
    let label = if language.is_empty() {
        "Text"
    } else {
        language
    };
    Ok(format!(
        "<div class=\"code-block\"><div class=\"code-toolbar\"><span>{}</span><button type=\"button\" data-copy=\"code\" aria-label=\"Copy code\">Copy</button></div><pre><code>{}</code></pre></div>",
        escape(label),
        crate::highlight::render(language, code)?
    ))
}

pub fn render(source: &str, media_dir: &Path) -> Result<RenderedMarkdown> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS;
    let fingerprint = format!("{:x}", Sha256::digest(source.as_bytes()));
    let prefix = format!("BLOGMATH{}", &fingerprint[..32]);
    let (prepared, extracted) = extract_math(source, options, &prefix);
    let mut events = Vec::new();
    let mut math = crate::math::Renderer::default();
    let mut formulas = std::collections::BTreeMap::new();
    let mut math_fonts = BTreeSet::new();
    for event in Parser::new_ext(&prepared, options) {
        if let Event::Text(value) = event {
            let mut remaining = value.as_ref();
            while let Some(start) = remaining.find(&prefix) {
                if start > 0 {
                    events.push(Event::Text(remaining[..start].to_owned().into()));
                }
                let tail = &remaining[start + prefix.len()..];
                let length = tail
                    .find("END")
                    .context("Unclosed generated formula placeholder")?;
                let index: usize = tail[..length]
                    .parse()
                    .context("Invalid generated formula placeholder")?;
                let extracted = &extracted[index];
                let formula = math
                    .render(extracted.tex, extracted.display)
                    .with_context(|| {
                        let prefix = &source[..extracted.offset];
                        format!(
                            "LaTeX at Markdown line {}, column {}",
                            prefix.bytes().filter(|b| *b == b'\n').count() + 1,
                            prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1
                        )
                    })?;
                math_fonts.extend(formula.fonts.iter().cloned());
                formulas.insert(events.len(), formula);
                events.push(if extracted.display {
                    Event::DisplayMath(extracted.tex.into())
                } else {
                    Event::InlineMath(extracted.tex.into())
                });
                remaining = &tail[length + 3..];
            }
            if !remaining.is_empty() {
                events.push(Event::Text(remaining.to_owned().into()));
            }
        } else {
            events.push(event);
        }
    }
    // Each placeholder is bound to this exact source. The sanitizer sees only
    // an empty span, never generated SVG/MathML or a broader HTML allowlist.
    let slot = |index: usize| format!("<span id=\"math-{}-{index}\"></span>", &fingerprint[..32]);
    let mut output = Vec::new();
    let mut headings = Vec::new();
    let mut used_ids = HashSet::new();
    let mut text = String::new();
    let mut cursor = 0;

    while cursor < events.len() {
        match &events[cursor] {
            Event::TaskListMarker(checked) => {
                output.push(Event::Html(
                    format!(
                        "<input type=\"checkbox\" disabled{} aria-label=\"{}\">",
                        if *checked { " checked" } else { "" },
                        escape(&task_label(&events[cursor + 1..]))
                    )
                    .into(),
                ));
            }
            Event::Start(Tag::Heading { level, .. }) => {
                let level = (*level as u8).max(2);
                let start = cursor + 1;
                cursor = start;
                let mut title = String::new();
                while !matches!(&events[cursor], Event::End(TagEnd::Heading(_))) {
                    if let Event::Text(value) | Event::Code(value) = &events[cursor] {
                        title.push_str(value);
                    } else if let Some(formula) = formulas.get(&cursor) {
                        title.push_str(&formula.text);
                    }
                    cursor += 1;
                }
                let id = heading_id(&title, &mut used_ids);
                output.push(Event::Html(format!("<h{level} id=\"{id}\">").into()));
                for (index, event) in events.iter().enumerate().take(cursor).skip(start) {
                    output.push(if formulas.contains_key(&index) {
                        Event::Html(slot(index).into())
                    } else {
                        event.clone()
                    });
                }
                output.push(Event::Html(
                    format!("<a class=\"heading-anchor\" href=\"#{id}\" aria-label=\"Link to heading\">#</a></h{level}>").into(),
                ));
                text.push_str(&title);
                text.push(' ');
                headings.push(Heading {
                    id,
                    text: title,
                    level,
                });
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                let language = match kind {
                    CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or(""),
                    CodeBlockKind::Indented => "",
                };
                let mut code = String::new();
                cursor += 1;
                while !matches!(&events[cursor], Event::End(TagEnd::CodeBlock)) {
                    if let Event::Text(value) = &events[cursor] {
                        code.push_str(value);
                    }
                    cursor += 1;
                }
                text.push_str(&code);
                text.push(' ');
                output.push(Event::Html(code_block(language, &code)?.into()));
            }
            Event::Start(Tag::Image {
                dest_url, title, ..
            }) => {
                let mut alt = String::new();
                cursor += 1;
                while !matches!(&events[cursor], Event::End(TagEnd::Image)) {
                    if let Event::Text(value) | Event::Code(value) = &events[cursor] {
                        alt.push_str(value);
                    } else if let Some(formula) = formulas.get(&cursor) {
                        alt.push_str(&formula.text);
                    }
                    cursor += 1;
                }
                let dimensions = if let Some(relative) = dest_url.strip_prefix("/media/") {
                    let size = imagesize::size(media_dir.join(relative))
                        .with_context(|| format!("Read image dimensions: {dest_url}"))?;
                    format!(" width=\"{}\" height=\"{}\"", size.width, size.height)
                } else {
                    String::new()
                };
                output.push(Event::Html(format!(
                    "<img src=\"{}\" alt=\"{}\" title=\"{}\"{dimensions} loading=\"lazy\" decoding=\"async\">",
                    escape(dest_url), escape(&alt), escape(title)
                ).into()));
                text.push_str(&alt);
                text.push(' ');
            }
            Event::InlineMath(_) | Event::DisplayMath(_) => {
                text.push_str(&formulas[&cursor].text);
                text.push(' ');
                output.push(Event::Html(slot(cursor).into()));
            }
            event => {
                match event {
                    Event::Text(value) | Event::Code(value) => text.push_str(value),
                    Event::SoftBreak | Event::HardBreak | Event::End(_) => text.push(' '),
                    _ => {}
                }
                output.push(event.clone());
            }
        }
        cursor += 1;
    }

    let mut rendered = String::new();
    html::push_html(&mut rendered, output.into_iter());
    let mut html = ammonia::Builder::default()
        .add_tags(["button", "input"])
        .add_generic_attributes(["class", "id", "lang", "dir", "aria-label"])
        .add_tag_attributes("button", ["type", "data-copy"])
        .add_tag_attributes("input", ["type", "checked", "disabled"])
        .add_tag_attributes("img", ["loading", "decoding", "width", "height"])
        .clean(&rendered)
        .to_string();
    for (index, formula) in formulas {
        let marker = slot(index);
        if html.contains(&marker) {
            anyhow::ensure!(
                html.matches(&marker).count() == 1,
                "Duplicate generated formula placeholder"
            );
            html = html.replacen(&marker, &formula.html, 1);
        }
    }
    Ok(RenderedMarkdown {
        content: PostContent { html, headings },
        text: text.split_whitespace().collect::<Vec<_>>().join(" "),
        math_fonts,
        has_math: !extracted.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn math_preserves_markdown_structure_code_and_original_source() {
        let source = r#"## The value $x^2$

$$
\begin{pmatrix}1&2\\3&4\end{pmatrix}
=
\begin{pmatrix}a&b\\c&d\end{pmatrix}
$$

The text $\text{cost $x$}$ contains nested math.

| A | B |
| - | - |
| $\alpha$ | $\beta$ |

- A root \(\sqrt{2}\).

\[\gdef\mathR{\mathbb{R}}\mathR\]

Use $\mathR$ again.

`$not_math$` and \$literal.

```rust
let price = "$not_math$";
```

<script>$\unknown$</script>"#;
        let rendered = render(source, Path::new(".")).unwrap();
        assert_eq!(rendered.content.headings.len(), 1);
        assert_eq!(rendered.content.headings[0].text, "The value x^2");
        assert_eq!(rendered.content.html.matches("<semantics>").count(), 8);
        assert!(rendered.content.html.contains("<table>"));
        assert!(rendered.content.html.contains("<li>"));
        assert!(rendered.content.html.contains("<code>$not_math$</code>"));
        assert!(rendered.content.html.contains("$literal"));
        assert!(!rendered.content.html.contains("<script"));
        assert!(rendered.content.html.contains("cost $x$"));
        assert!(rendered.math_fonts.contains("AMS-Regular"));
        assert!(render("$\u{005c}mathR$", Path::new(".")).is_err());
        let error = render("A paragraph.\n\n$\\sqrt{$", Path::new("."))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("line 3"), "{error}");
        let link = render(
            "[The value $x$](https://example.com/a$raw$)",
            Path::new("."),
        )
        .unwrap();
        assert!(
            link.content
                .html
                .contains("href=\"https://example.com/a$raw$\"")
        );
        assert_eq!(link.content.html.matches("<semantics>").count(), 1);
        let rule = render(r"$$\rule{2em}{1ex}$$", Path::new(".")).unwrap();
        assert!(rule.has_math);
        assert!(rule.math_fonts.is_empty());
    }

    #[test]
    fn renders_article_features_with_safe_html_and_unique_anchors() {
        let source = "## Hello\n\n## Hello\n\n## Hello-2\n\n## 世界\n\n| A | B |\n| - | - |\n| 1 | 2 |\n\n- [x] Done\n\nA note[^one].\n\n[^one]: Footnote.\n\n```rust\nfn main() { println!(\"Hello\"); }\n```\n\n<script>alert('bad')</script>";
        let rendered = render(source, Path::new(".")).unwrap();
        let ids: Vec<_> = rendered
            .content
            .headings
            .iter()
            .map(|heading| heading.id.as_str())
            .collect();
        assert_eq!(ids, ["hello", "hello-2", "hello-2-2", "世界"]);
        assert!(rendered.content.html.contains("<table>"));
        assert!(rendered.content.html.contains("data-copy=\"code\""));
        assert!(rendered.content.html.contains("syntax-"));
        assert!(rendered.content.html.contains("checkbox"));
        assert!(rendered.content.html.contains("aria-label=\"Done\""));
        assert!(rendered.content.html.contains("footnote"));
        assert!(!rendered.content.html.contains("<script"));
    }
}
