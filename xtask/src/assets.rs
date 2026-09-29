use std::{collections::HashMap, fs, path::Path};

use anyhow::{Result, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use oxc::{
    allocator::Allocator,
    ast::ast::{IdentifierName, PropertyKey},
    ast_visit::{VisitMut, walk_mut},
    codegen::{Codegen, CodegenOptions, CommentOptions},
    minifier::{Minifier, MinifierOptions},
    parser::Parser,
    span::SourceType,
};
use sha2::{Digest, Sha256, Sha384};
use wasm_encoder::{
    ImportSection, Module, RawSection,
    reencode::{Reencode, RoundtripReencoder},
};
use wasmparser::{Parser as WasmParser, Payload};

struct ImportNames<'a> {
    allocator: &'a Allocator,
    names: &'a HashMap<String, String>,
}

impl<'a> VisitMut<'a> for ImportNames<'a> {
    fn visit_identifier_name(&mut self, identifier: &mut IdentifierName<'a>) {
        if let Some(name) = self.names.get(identifier.name.as_str()) {
            identifier.name = self.allocator.alloc_str(name).into();
        }
    }

    fn visit_property_key(&mut self, key: &mut PropertyKey<'a>) {
        if let PropertyKey::StringLiteral(literal) = key
            && let Some(name) = self.names.get(literal.value.as_str())
        {
            literal.value = self.allocator.alloc_str(name).into();
            literal.raw = None;
        }
        walk_mut::walk_property_key(self, key);
    }
}

fn compact_name(name: &str, names: &mut HashMap<String, String>) -> String {
    let next = format!("i{}", names.len());
    names.entry(name.to_owned()).or_insert(next).clone()
}

// Import names are shared only between this module and its generated JS glue.
fn compact_imports(bytes: &[u8], names: &mut HashMap<String, String>) -> Result<Vec<u8>> {
    let mut module = Module::new();
    for payload in WasmParser::new(0).parse_all(bytes) {
        let payload = payload?;
        if let Payload::ImportSection(reader) = payload {
            let mut section = ImportSection::new();
            for import in reader.into_imports() {
                let import = import?;
                let module = compact_name(import.module, names);
                let name = compact_name(import.name, names);
                section.import(&module, &name, RoundtripReencoder.entity_type(import.ty)?);
            }
            module.section(&section);
        } else if let Some((id, range)) = payload.as_section() {
            module.section(&RawSection {
                id,
                data: &bytes[range],
            });
        }
    }
    Ok(module.finish())
}

fn integrity(bytes: &[u8]) -> String {
    format!("sha384-{}", BASE64_STANDARD.encode(Sha384::digest(bytes)))
}

fn minify(source: &str, names: &HashMap<String, String>) -> Result<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "Invalid generated JavaScript"
    );
    let mut program = parsed.program;
    ImportNames {
        allocator: &allocator,
        names,
    }
    .visit_program(&mut program);
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

pub fn optimize(dist: &Path, mut template: String) -> Result<String> {
    let entries = fs::read_dir(dist.join("assets"))?.collect::<std::io::Result<Vec<_>>>()?;
    let mut names = HashMap::new();
    for extension in ["wasm", "js"] {
        for entry in &entries {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(extension) {
                continue;
            }
            let original = fs::read(&path)?;
            let bytes = if extension == "js" {
                minify(std::str::from_utf8(&original)?, &names)?.into_bytes()
            } else {
                compact_imports(&original, &mut names)?
            };
            let hash = format!("{:x}", Sha256::digest(&bytes));
            let name = format!("app-{}.{extension}", &hash[..16]);
            let old_name = path.file_name().unwrap().to_str().unwrap();
            template = template.replace(&integrity(&original), &integrity(&bytes));
            fs::write(path.with_file_name(&name), bytes)?;
            template = template.replace(old_name, &name);
            if name != old_name {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(template)
}
