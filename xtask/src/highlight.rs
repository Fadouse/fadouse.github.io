use std::{borrow::Cow, cell::RefCell, sync::OnceLock};

use anyhow::{Context, Result, anyhow};
use shared::escape_html_into;
use syntect::{
    html::{ClassStyle, ClassedHTMLGenerator},
    parsing::SyntaxSet,
    util::LinesWithEndings,
};
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

const CAPTURES: &[&str] = &[
    "attribute",
    "boolean",
    "character",
    "comment",
    "constant",
    "constructor",
    "embedded",
    "escape",
    "keyword",
    "function",
    "label",
    "module",
    "number",
    "operator",
    "property",
    "punctuation",
    "string",
    "tag",
    "type",
    "variable",
    "variable.builtin",
];

#[derive(Clone, Copy)]
enum Grammar {
    Rust,
    Python,
    JavaScript,
    C,
    Bash,
    Zig,
    Java,
    Assembly,
    Cpp,
}

impl Grammar {
    fn for_token(token: &str) -> Option<Self> {
        Some(match token.to_ascii_lowercase().as_str() {
            "rust" | "rs" => Self::Rust,
            "python" | "py" => Self::Python,
            "javascript" | "js" | "jsx" => Self::JavaScript,
            "c" | "h" => Self::C,
            "bash" | "sh" | "shell" => Self::Bash,
            "zig" => Self::Zig,
            "java" => Self::Java,
            "asm" | "assembly" | "nasm" | "x86asm" | "armasm" | "s" => Self::Assembly,
            "cpp" | "c++" | "cxx" | "cc" | "hpp" | "h++" => Self::Cpp,
            _ => return None,
        })
    }

    fn configuration(self) -> Result<&'static HighlightConfiguration> {
        static CONFIGURATIONS: [OnceLock<Result<HighlightConfiguration>>; 9] =
            [const { OnceLock::new() }; 9];
        CONFIGURATIONS[self as usize]
            .get_or_init(|| self.create_configuration())
            .as_ref()
            .map_err(|error| anyhow!("Initialize syntax highlighting: {error:#}"))
    }

    fn create_configuration(self) -> Result<HighlightConfiguration> {
        let (language, name, query, locals) = match self {
            Self::Rust => (
                tree_sitter_rust::LANGUAGE,
                "rust",
                Cow::Borrowed(tree_sitter_rust::HIGHLIGHTS_QUERY),
                "",
            ),
            Self::Python => (
                tree_sitter_python::LANGUAGE,
                "python",
                Cow::Borrowed(tree_sitter_python::HIGHLIGHTS_QUERY),
                "",
            ),
            Self::JavaScript => (
                tree_sitter_javascript::LANGUAGE,
                "javascript",
                Cow::Owned(format!(
                    "{}\n{}",
                    tree_sitter_javascript::HIGHLIGHT_QUERY,
                    tree_sitter_javascript::JSX_HIGHLIGHT_QUERY
                )),
                tree_sitter_javascript::LOCALS_QUERY,
            ),
            Self::C => (
                tree_sitter_c::LANGUAGE,
                "c",
                Cow::Borrowed(tree_sitter_c::HIGHLIGHT_QUERY),
                "",
            ),
            Self::Bash => (
                tree_sitter_bash::LANGUAGE,
                "bash",
                Cow::Borrowed(tree_sitter_bash::HIGHLIGHT_QUERY),
                "",
            ),
            Self::Zig => (
                tree_sitter_zig::LANGUAGE,
                "zig",
                // These upstream Lua patterns also use valid regex syntax. The
                // native query engine evaluates match?, but not lua-match?.
                Cow::Owned(tree_sitter_zig::HIGHLIGHTS_QUERY.replace("#lua-match?", "#match?")),
                "",
            ),
            Self::Java => (
                tree_sitter_java::LANGUAGE,
                "java",
                Cow::Borrowed(tree_sitter_java::HIGHLIGHTS_QUERY),
                "",
            ),
            Self::Assembly => (
                tree_sitter_asm::LANGUAGE,
                "asm",
                Cow::Borrowed(tree_sitter_asm::HIGHLIGHTS_QUERY),
                "",
            ),
            Self::Cpp => (
                tree_sitter_cpp::LANGUAGE,
                "cpp",
                // The C++ query extends C rather than repeating its base rules.
                Cow::Owned(format!(
                    "{}\n{}",
                    tree_sitter_c::HIGHLIGHT_QUERY,
                    tree_sitter_cpp::HIGHLIGHT_QUERY
                )),
                "",
            ),
        };
        let mut configuration =
            HighlightConfiguration::new(language.into(), name, &query, "", locals)
                .with_context(|| format!("Compile {name} syntax queries"))?;
        configuration.configure(CAPTURES);
        Ok(configuration)
    }
}

pub fn render(language: &str, code: &str) -> Result<String> {
    if let Some(grammar) = Grammar::for_token(language) {
        thread_local! {
            static HIGHLIGHTER: RefCell<Highlighter> = RefCell::new(Highlighter::new());
        }
        let configuration = grammar.configuration()?;
        return HIGHLIGHTER.with(|highlighter| {
            let mut highlighter = highlighter.borrow_mut();
            let events =
                highlighter.highlight(configuration, code.as_bytes(), None, None, |_| None)?;
            let mut html = String::with_capacity(code.len());
            for event in events {
                match event? {
                    HighlightEvent::Source { start, end } => {
                        escape_html_into(&code[start..end], &mut html);
                    }
                    HighlightEvent::HighlightStart(highlight) => {
                        html.push_str("<span class=\"syntax-");
                        html.push_str(&CAPTURES[highlight.0].replace('.', "-"));
                        html.push_str("\">");
                    }
                    HighlightEvent::HighlightEnd => html.push_str("</span>"),
                }
            }
            Ok(html)
        });
    }

    // Retain the existing language coverage outside the syntax-tree grammars.
    static SYNTAXES: OnceLock<SyntaxSet> = OnceLock::new();
    let syntaxes = SYNTAXES.get_or_init(SyntaxSet::load_defaults_newlines);
    let Some(syntax) = syntaxes.find_syntax_by_token(language) else {
        return Ok(shared::escape_html(code));
    };
    let mut generator = ClassedHTMLGenerator::new_with_class_style(
        syntax,
        syntaxes,
        ClassStyle::SpacedPrefixed { prefix: "syntax-" },
    );
    for line in LinesWithEndings::from(code) {
        generator.parse_html_for_line_which_includes_newline(line)?;
    }
    Ok(generator.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_syntax_structures_in_nine_languages() {
        let fixtures = [
            (
                "rust",
                "fn greet() { println!(\"hello\"); }",
                "function",
                "greet",
            ),
            (
                "python",
                "def greet():\n    return \"hello\"\n",
                "function",
                "greet",
            ),
            (
                "javascript",
                "function greet() { return \"hello\"; }",
                "function",
                "greet",
            ),
            ("c", "int greet(void) { return 42; }", "function", "greet"),
            (
                "bash",
                "greet() { printf '%s\\n' hello; }",
                "function",
                "greet",
            ),
            (
                "zig",
                "pub fn greet() []const u8 { return \"hello\"; }",
                "function",
                "greet",
            ),
            (
                "java",
                "class Main { String greet() { return \"hello\"; } }",
                "function",
                "greet",
            ),
            (
                "asm",
                "greet:\n    mov rax, 42\n    ret\n",
                "label",
                "greet",
            ),
            (
                "cpp",
                "template <typename T> T greet() { return T{42}; }",
                "function",
                "greet",
            ),
        ];
        for (language, code, class, token) in fixtures {
            let html = render(language, code).unwrap();
            assert!(
                html.contains(&format!("<span class=\"syntax-{class}\">{token}</span>")),
                "{language}: {html}"
            );
        }
    }

    #[test]
    fn cpp_inherits_base_rules_and_handles_raw_strings() {
        let html = render(
            "c++",
            "class Greeter { int greet() { return 42; } };\nauto s = R\"(hello)\";",
        )
        .unwrap();
        for token in ["class", "return"] {
            assert!(
                html.contains(&format!("<span class=\"syntax-keyword\">{token}</span>")),
                "{html}"
            );
        }
        assert!(html.contains("<span class=\"syntax-number\">42</span>"));
        assert!(html.contains("<span class=\"syntax-string\">R&quot;(hello)&quot;</span>"));
    }

    #[test]
    fn zig_predicates_do_not_treat_every_identifier_as_a_type() {
        let html = render(
            "zig",
            "const Foo = struct {}; var value: Foo = undefined; const LIMIT = 42; fn greet() void {}",
        )
        .unwrap();
        assert!(
            html.contains("<span class=\"syntax-type\">Foo</span>"),
            "{html}"
        );
        assert!(
            html.contains("<span class=\"syntax-variable\">value</span>"),
            "{html}"
        );
        assert!(
            !html.contains("<span class=\"syntax-type\">value</span>"),
            "{html}"
        );
        assert!(
            html.contains("<span class=\"syntax-constant\">LIMIT</span>"),
            "{html}"
        );
        assert!(
            html.contains("<span class=\"syntax-keyword\">fn</span>"),
            "{html}"
        );
    }

    #[test]
    fn language_aliases_and_existing_languages_remain_highlighted() {
        for (aliases, code) in [
            (&["rs", "RUST"][..], "fn greet() {}"),
            (&["py"][..], "def greet(): pass"),
            (&["js", "jsx"][..], "function greet() {}"),
            (&["h"][..], "int greet(void);"),
            (&["sh", "shell"][..], "greet() { echo hello; }"),
            (
                &["assembly", "nasm", "x86asm", "armasm", "s"][..],
                "greet:\nret\n",
            ),
            (&["c++", "cxx", "cc", "hpp", "h++"][..], "int greet() {}"),
        ] {
            for alias in aliases {
                assert!(render(alias, code).unwrap().contains("syntax-"), "{alias}");
            }
        }
        assert!(
            render("sql", "SELECT * FROM greetings;")
                .unwrap()
                .contains("syntax-keyword")
        );
        assert_eq!(
            render("greeting", "hello -> world\n").unwrap(),
            "hello -&gt; world\n"
        );
    }

    #[test]
    fn assembly_highlights_instructions_registers_and_labels() {
        for (code, register) in [
            ("greet:\n    mov rax, 42\n    ret\n", "rax"),
            ("greet:\n    mov $42, %eax\n    ret\n", "%eax"),
            ("greet:\n    mov x0, #42\n    ret\n", "x0"),
        ] {
            let html = render("asm", code).unwrap();
            assert!(
                html.contains("<span class=\"syntax-function\">mov</span>"),
                "{html}"
            );
            assert!(
                html.contains("<span class=\"syntax-label\">greet</span>"),
                "{html}"
            );
            assert!(
                html.contains(&format!(
                    "<span class=\"syntax-variable-builtin\">{register}</span>"
                )),
                "{html}"
            );
        }
    }

    #[test]
    fn javascript_tracks_local_names_and_jsx_structure() {
        let html = render(
            "jsx",
            "function View(console) { return <span>{console}</span>; }",
        )
        .unwrap();
        assert!(
            html.contains("<span class=\"syntax-tag\">span</span>"),
            "{html}"
        );
        assert!(
            !html.contains("<span class=\"syntax-variable-builtin\">console</span>"),
            "{html}"
        );
    }

    #[test]
    fn escapes_code_and_recovers_incomplete_fragments() {
        let code = "// 你好 👋 <script> & \"quoted\"\nfn greet() {\n\tlet x = \"<&>\";\n";
        let html = render("rust", code).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("你好 👋 &lt;script&gt; &amp; &quot;quoted&quot;"));
        assert!(
            html.contains("<span class=\"syntax-keyword\">fn</span>"),
            "{html}"
        );
        assert!(html.contains("greet"));
        assert!(html.ends_with('\n'));
        assert!(html.contains('\t'));
        assert_eq!(
            render("greeting", "<script>&你好\n").unwrap(),
            "&lt;script&gt;&amp;你好\n"
        );
    }
}
