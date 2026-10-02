use std::{collections::BTreeMap, env, fs, path::PathBuf};
use syn::visit::Visit;
fn main() {
    println!("cargo:rerun-if-changed=dom.json");
    literals();
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

fn literals() {
    #[derive(Default)]
    struct Collector {
        values: BTreeMap<String, String>,
        uses: BTreeMap<String, usize>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("lit") {
                let value: syn::LitStr = syn::parse2(node.tokens.clone()).unwrap();
                *self.uses.entry(value.value()).or_default() += 1;
                self.values.insert(value.token().to_string(), value.value());
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let mut collector = Collector::default();
    println!("cargo:rerun-if-changed=src");
    for entry in fs::read_dir("src").unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(path).unwrap();
            collector.visit_file(&syn::parse_file(&source).unwrap());
        }
    }
    let mut values: Vec<_> = collector.values.values().collect();
    // Spend the one-byte signed immediate range on frequent short strings.
    // Remaining strings stay longest-first to share complete UTF-8 suffixes.
    values.sort_by_key(|value| {
        (
            core::cmp::Reverse(collector.uses[*value] * 1024 / (value.len() + 1)),
            core::cmp::Reverse(value.len()),
        )
    });
    let mut compact_bytes = 0;
    let mut compact = Vec::new();
    let mut remaining = Vec::new();
    for value in values {
        if collector.uses[value] >= 3 && compact_bytes + value.len() < 62 {
            compact_bytes += value.len() + 1;
            compact.push(value);
        } else {
            remaining.push(value);
        }
    }
    remaining.sort_by_key(|value| core::cmp::Reverse(value.len()));
    compact.extend(remaining);
    let values = compact;
    let mut pool = Vec::new();
    let mut offsets = BTreeMap::new();
    for value in values {
        assert!(!value.contains('\0'), "Literal contains a NUL");
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        // A shorter literal can borrow a complete NUL-terminated suffix.
        // Offsets point to the same UTF-8 bytes, without runtime decompression.
        let offset = pool.windows(bytes.len()).position(|suffix| suffix == bytes);
        let offset = offset.unwrap_or_else(|| {
            let offset = pool.len();
            pool.extend_from_slice(&bytes);
            offset
        });
        offsets.insert(value, offset);
    }
    let mut source = String::from("macro_rules! lit {\n");
    for (token, value) in &collector.values {
        let offset = offsets[value];
        source.push_str(&format!(
            "    ({token}) => {{ $crate::browser::Literal(u32::MAX - 2 - {offset}) }};\n"
        ));
    }
    assert!(
        pool.len() < 4094,
        "Literal pool exceeds the compact argument range"
    );
    source.push_str("}\n");
    source.push_str(&format!("pub static LITERALS: &[u8] = &{pool:?};\n"));
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("literals.rs"),
        source,
    )
    .unwrap();
}
