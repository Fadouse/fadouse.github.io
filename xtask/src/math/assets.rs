use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub struct Assets {
    pub css: String,
    pub fonts: BTreeMap<String, String>,
}
fn write(dist: &Path, prefix: &str, extension: &str, bytes: &[u8]) -> Result<String> {
    let hash = format!("{:x}", Sha256::digest(bytes));
    let name = format!("{prefix}-{}.{extension}", &hash[..16]);
    fs::write(dist.join("assets").join(&name), bytes)?;
    Ok(format!("/assets/{name}"))
}
pub fn publish(root: &Path, dist: &Path, used: &BTreeSet<String>) -> Result<Assets> {
    let mut css = include_str!("style.css").to_owned();
    let mut fonts = BTreeMap::new();
    let mut font_bytes = 0;
    for name in used {
        let data = fs::read(root.join(format!("xtask/src/math/fonts/KaTeX_{name}.woff2")))?;
        font_bytes += data.len();
        let url = write(dist, &format!("math-{name}"), "woff2", &data)?;
        css.push_str(&format!("@font-face{{font-family:BlogMath-{name};src:url('{url}') format('woff2');font-display:block}}"));
        fonts.insert(name.clone(), url);
    }
    write(dist, "math-LICENSE", "txt", include_bytes!("LICENSE"))?;
    println!(
        "Math styles: {} bytes; {} local math fonts: {} bytes.",
        css.len(),
        fonts.len(),
        font_bytes
    );
    Ok(Assets { css, fonts })
}
