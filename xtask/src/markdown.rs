use std::{collections::HashSet, path::Path, sync::OnceLock};

use anyhow::{Context, Result};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd, html};
use shared::{Heading, PostContent, normalize};
use syntect::{
    html::{ClassStyle, ClassedHTMLGenerator},
    parsing::SyntaxSet,
    util::LinesWithEndings,
};

pub struct RenderedMarkdown {
    pub content: PostContent,
    pub text: String,
}

pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
    static SYNTAXES: OnceLock<SyntaxSet> = OnceLock::new();
    let syntaxes = SYNTAXES.get_or_init(SyntaxSet::load_defaults_newlines);
    let syntax = syntaxes
        .find_syntax_by_token(language)
        .unwrap_or_else(|| syntaxes.find_syntax_plain_text());
    let mut generator = ClassedHTMLGenerator::new_with_class_style(
        syntax,
        syntaxes,
        ClassStyle::SpacedPrefixed { prefix: "syntax-" },
    );
    for line in LinesWithEndings::from(code) {
        generator.parse_html_for_line_which_includes_newline(line)?;
    }
    let label = if language.is_empty() {
        "Text"
    } else {
        language
    };
    Ok(format!(
        "<div class=\"code-block\"><div class=\"code-toolbar\"><span>{}</span><button type=\"button\" data-copy=\"code\" aria-label=\"Copy code\">Copy</button></div><pre><code>{}</code></pre></div>",
        escape(label),
        generator.finalize()
    ))
}

pub fn render(source: &str, media_dir: &Path) -> Result<RenderedMarkdown> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS;
    let events: Vec<_> = Parser::new_ext(source, options).collect();
    let mut output = Vec::new();
    let mut headings = Vec::new();
    let mut used_ids = HashSet::new();
    let mut text = String::new();
    let mut cursor = 0;

    while cursor < events.len() {
        match &events[cursor] {
            Event::Start(Tag::Heading { level, .. }) => {
                let level = (*level as u8).max(2);
                let start = cursor + 1;
                cursor = start;
                let mut title = String::new();
                while !matches!(&events[cursor], Event::End(TagEnd::Heading(_))) {
                    if let Event::Text(value) | Event::Code(value) = &events[cursor] {
                        title.push_str(value);
                    }
                    cursor += 1;
                }
                let id = heading_id(&title, &mut used_ids);
                output.push(Event::Html(format!("<h{level} id=\"{id}\">").into()));
                output.extend(events[start..cursor].iter().cloned());
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
    let html = ammonia::Builder::default()
        .add_tags(["button", "input"])
        .add_generic_attributes(["class", "id", "lang", "dir", "aria-label"])
        .add_tag_attributes("button", ["type", "data-copy"])
        .add_tag_attributes("input", ["type", "checked", "disabled"])
        .add_tag_attributes("img", ["loading", "decoding", "width", "height"])
        .clean(&rendered)
        .to_string();
    Ok(RenderedMarkdown {
        content: PostContent { html, headings },
        text: text.split_whitespace().collect::<Vec<_>>().join(" "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(rendered.content.html.contains("footnote"));
        assert!(!rendered.content.html.contains("<script"));
    }
}
