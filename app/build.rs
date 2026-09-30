use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-changed=dom.json");
    let keys: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&fs::read_to_string("dom.json").unwrap()).unwrap();
    // Signed indices in -64..=63 use one-byte WASM i32 constants. The host
    // adds the same offset when looking up the unchanged browser names.
    assert!(
        keys.len() <= 128,
        "Browser keys exceed the compact signed range"
    );
    let mut source = String::from(
        "#[derive(Clone, Copy)]\n#[repr(i8)]\n#[allow(clippy::enum_variant_names)]\npub enum Key {\n",
    );
    for (index, name) in keys.keys().enumerate() {
        source.push_str(&format!("    {name} = {},\n", index as i32 - 64));
    }
    source.push_str("}\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("keys.rs"),
        source,
    )
    .unwrap();
}
