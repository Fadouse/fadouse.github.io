use super::*;

#[test]
fn accessible_math_preserves_matrix_fences_and_script_style() {
    let mut renderer = Renderer::default();
    let matrix = renderer
        .render(r"\begin{pmatrix}1&2\\3&4\end{pmatrix}", true)
        .unwrap();
    let semantics = matrix.html.split("</semantics>").next().unwrap();
    assert!(semantics.contains("<mo fence=\"true\">(</mo>"));
    assert!(semantics.contains("<mo fence=\"true\">)</mo>"));
    assert_eq!(semantics.matches("<mtd>").count(), 4);
    let small = renderer
        .render(r"\begin{smallmatrix}1&2\end{smallmatrix}", true)
        .unwrap();
    assert!(small.html.contains("scriptlevel=\"1\""));
    assert!(
        renderer
            .render(r"\underbrace{x}", true)
            .unwrap()
            .html
            .contains("<munder accentunder=\"true\">")
    );
}

#[test]
fn equation_numbering_suppression_and_article_scope() {
    let mut renderer = Renderer::default();
    let aligned = renderer
        .render(r"\begin{align}a&=b\\c&=d\notag\\e&=f\end{align}", true)
        .unwrap();
    assert!(aligned.html.contains("<mtext>(1)</mtext>"));
    assert!(aligned.html.contains("<mtext>(2)</mtext>"));
    assert_eq!(aligned.html.matches("<mlabeledtr>").count(), 2);
    let equation = renderer
        .render(r"\begin{equation}x=y\end{equation}", true)
        .unwrap();
    assert!(equation.html.contains("<mtext>(3)</mtext>"));
    assert!(
        !renderer
            .render(r"\begin{equation*}x=y\end{equation*}", true)
            .unwrap()
            .html
            .contains("<mlabeledtr>")
    );
    assert!(
        Renderer::default()
            .render(r"\begin{equation}x=y\end{equation}", true)
            .unwrap()
            .html
            .contains("<mtext>(1)</mtext>")
    );
}

#[test]
fn official_macro_and_unicode_semantics() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("tests/equivalent.json")).unwrap();
    let mut failures = Vec::new();
    for case in cases.as_array().unwrap() {
        let actual = Renderer::default().render(case["tex"].as_str().unwrap(), false);
        let expected = Renderer::default().render(case["equivalent"].as_str().unwrap(), false);
        match (actual, expected) {
            (Ok(actual), Ok(expected)) if actual.text == expected.text => {}
            (actual, expected) => failures.push(format!(
                "line {}: {} => {:?}, expected {:?}",
                case["line"],
                case["tex"],
                actual.map(|r| r.text),
                expected.map(|r| r.text)
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reference_formula_categories_parse_and_render() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("tests/reference.json")).unwrap();
    let mut failures = Vec::new();
    let mut gallery = String::new();
    let mut fonts = std::collections::BTreeSet::new();
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let source = case["tex"].as_str().unwrap();
        if case["invalid"].as_bool().unwrap_or(false) {
            assert!(Renderer::default().render(source, false).is_err(), "{name}");
            continue;
        }
        match Renderer::default().render(source, case["display"].as_bool().unwrap()) {
            Ok(rendered) => {
                assert!(rendered.html.contains("<semantics>"), "{name}");
                assert!(!rendered.html.contains("NaN"), "{name}");
                fonts.extend(rendered.fonts);
                gallery.push_str(&format!(
                    "<section id=\"{name}\"><h2>{name}</h2>{}<pre>{}</pre></section>",
                    rendered.html,
                    shared::escape_html(source)
                ));
            }
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    if let Ok(path) = std::env::var("MATH_GALLERY") {
        let directory = std::path::Path::new(&path);
        std::fs::create_dir_all(directory.join("assets")).unwrap();
        let source = "\r\n\\text{你好 α ≤ β 🧮}\\quad x_1^2\r\n +\\frac{é}{2}\r\n";
        let rendered = Renderer::default().render(source, true).unwrap();
        std::fs::write(
            directory.join("math-source.json"),
            serde_json::to_vec(&serde_json::json!({"tex": source, "html": rendered.html})).unwrap(),
        )
        .unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let assets = assets::publish(root, directory, &fonts).unwrap();
        std::fs::write(directory.join("assets/math-fixtures.css"), assets.css).unwrap();
        std::fs::write(directory.join("math-gallery.html"),format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Math layout fixtures</title><link rel=\"stylesheet\" href=\"/assets/math-fixtures.css\"><style>body{{font:20px/1.6 system-ui;margin:24px}}section{{padding:24px 0;border-bottom:1px solid #bbb}}h2{{font-size:16px}}pre{{font-size:12px;white-space:pre-wrap}}.math{{color:#202020}}</style><main>{gallery}</main></html>")).unwrap();
    }
}

#[test]
fn macro_scopes_global_definitions_and_errors() {
    let mut renderer = Renderer::default();
    assert_eq!(
        renderer
            .render(r"\def\a{a}{\def\a{b}\a}\a", false)
            .unwrap()
            .text,
        "ba"
    );
    assert_eq!(
        renderer
            .render(r"\gdef\mathR{\mathbb{R}}\mathR", false)
            .unwrap()
            .text,
        "R"
    );
    assert_eq!(renderer.render(r"\mathR", false).unwrap().text, "R");
    assert!(Renderer::default().render(r"\mathR", false).is_err());
    assert!(
        renderer
            .render(r"\def\loop{\loop}\loop", false)
            .unwrap_err()
            .message
            .contains("1000")
    );
    assert!(renderer.render(r"\sqrt{", false).is_err());
    assert!(renderer.render(r"a^b^c", false).is_err());
    let chain = "\\expandafter x".repeat(1500);
    assert!(
        renderer
            .render(&chain, false)
            .unwrap_err()
            .message
            .contains("1000")
    );
}

#[test]
fn documented_main_library_syntax() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("tests/documented.json")).unwrap();
    let mut failures = Vec::new();
    for case in cases.as_array().unwrap() {
        if let Err(error) = Renderer::default().render(
            case["tex"].as_str().unwrap(),
            case["display"].as_bool().unwrap(),
        ) {
            failures.push(format!("line {}: {error}", case["line"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn official_default_parser_acceptance_and_rejections() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("tests/parser.json")).unwrap();
    let mut failures = Vec::new();
    for case in cases.as_array().unwrap() {
        let result = Renderer::default().render(case["tex"].as_str().unwrap(), false);
        let expected = case["valid"].as_bool().unwrap();
        if result.is_ok() != expected {
            failures.push(format!(
                "line {} expected {}: {} ({})",
                case["line"],
                expected,
                case["tex"],
                result.err().map(|e| e.to_string()).unwrap_or_default()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
