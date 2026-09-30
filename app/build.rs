use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-changed=dom.json");
    let keys: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&fs::read_to_string("dom.json").unwrap()).unwrap();
    // Preserve browser property names, including altKey, metaKey and key.
    let mut source = String::from(
        "#[derive(Clone, Copy)]\n#[repr(u32)]\n#[allow(clippy::enum_variant_names)]\npub enum Key {\n",
    );
    for (index, name) in keys.keys().enumerate() {
        source.push_str(&format!("    {name} = {index},\n"));
    }
    source.push_str("}\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("keys.rs"),
        source,
    )
    .unwrap();
}
