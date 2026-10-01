use anyhow::{Result, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use oxc::{
    allocator::Allocator,
    codegen::{Codegen, CodegenOptions, CommentOptions},
    minifier::{Minifier, MinifierOptions},
    parser::Parser,
    span::SourceType,
};
use sha2::{Digest, Sha256, Sha384};
use std::{fs, path::Path};

fn integrity(bytes: &[u8]) -> String {
    format!("sha384-{}", BASE64_STANDARD.encode(Sha384::digest(bytes)))
}
fn minify(source: &str) -> Result<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "Invalid browser API bindings"
    );
    let mut program = parsed.program;
    let result = Minifier::new(MinifierOptions::default()).minify(&allocator, &mut program);
    Ok(Codegen::new()
        .with_options(CodegenOptions {
            minify: true,
            comments: CommentOptions::disabled(),
            ..CodegenOptions::default()
        })
        .with_scoping(result.scoping)
        .build(&program)
        .code)
}
fn write_asset(dist: &Path, extension: &str, bytes: &[u8]) -> Result<String> {
    let hash = format!("{:x}", Sha256::digest(bytes));
    let name = format!("app-{}.{extension}", &hash[..16]);
    fs::write(dist.join("assets").join(&name), bytes)?;
    Ok(format!("/assets/{name}"))
}
pub fn append_css(dist: &Path, template: &str, extra: &str) -> Result<String> {
    for (start, _) in template.match_indices("<link") {
        let end = start
            + template[start..]
                .find('>')
                .ok_or_else(|| anyhow::anyhow!("Unclosed stylesheet link"))?
            + 1;
        let tag = &template[start..end];
        if !tag.contains("rel=stylesheet") && !tag.contains("rel=\"stylesheet\"") {
            continue;
        }
        let href = &tag[tag
            .find("href=")
            .ok_or_else(|| anyhow::anyhow!("Stylesheet has no URL"))?
            + 5..];
        let url = if let Some(quote) = href.chars().next().filter(|c| *c == '\'' || *c == '\"') {
            href[1..].split(quote).next().unwrap()
        } else {
            href.split_ascii_whitespace()
                .next()
                .unwrap()
                .trim_end_matches('>')
        };
        let original = dist.join(url.trim_start_matches('/'));
        let mut css = fs::read(&original)?;
        css.extend_from_slice(extra.as_bytes());
        let url = write_asset(dist, "css", &css)?;
        let replacement = format!(
            "<link rel=\"stylesheet\" href=\"{url}\" integrity=\"{}\" crossorigin>",
            integrity(&css)
        );
        fs::remove_file(original)?;
        return Ok(format!(
            "{}{}{}",
            &template[..start],
            replacement,
            &template[end..]
        ));
    }
    anyhow::bail!("Missing Trunk stylesheet")
}
pub fn build(root: &Path, dist: &Path, template: String) -> Result<String> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| root.join("target"), |path| root.join(path));
    let wasm = fs::read(target.join("wasm32-unknown-unknown/release/app.wasm"))?;
    ensure!(
        wasm.len() < 25_000,
        "Compiled WASM is {} bytes; it must stay below 25,000 bytes",
        wasm.len()
    );
    // Ship the compiler output byte-for-byte: no WASM rewriting or compression.
    let wasm_url = write_asset(dist, "wasm", &wasm)?;
    let keys: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(root.join("app/dom.json"))?)?;
    let names: Vec<_> = keys.values().collect();
    let host = fs::read_to_string(root.join("app/host.js"))?
        .replace("__BROWSER_KEYS__", &serde_json::to_string(&names)?);
    let host = minify(&host)?.into_bytes();
    let host_url = write_asset(dist, "js", &host)?;
    println!(
        "Compiled WASM: {} bytes; browser API bindings: {} bytes.",
        wasm.len(),
        host.len()
    );
    Ok(template.replace("__BLOG_ASSETS__", &format!("import initialize from '{host_url}';await initialize('{wasm_url}','{}');", integrity(&wasm)))
        .replace("</head>", &format!("<link rel=\"modulepreload\" href=\"{host_url}\" integrity=\"{}\" crossorigin><link rel=\"preload\" as=\"fetch\" type=\"application/wasm\" href=\"{wasm_url}\" integrity=\"{}\" crossorigin></head>", integrity(&host), integrity(&wasm))))
}
