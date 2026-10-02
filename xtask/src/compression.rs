// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result};
use brotli::enc::BrotliEncoderParams;
use flate2::{Compression, write::GzEncoder};

fn compress(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(bytes)?;
    let gzip = gzip.finish()?;
    let mut encoded = Vec::new();
    brotli::BrotliCompress(
        &mut &bytes[..],
        &mut encoded,
        &BrotliEncoderParams {
            quality: 11,
            lgwin: 19,
            ..Default::default()
        },
    )?;
    Ok((gzip, encoded))
}

pub fn publish(dist: &Path) -> Result<()> {
    let mut entries = fs::read_dir(dist)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            publish(&path)?;
            continue;
        }
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !matches!(
            extension,
            "html" | "css" | "js" | "wasm" | "json" | "xml" | "txt" | "svg" | "bin"
        ) {
            continue;
        }
        let bytes = fs::read(&path)?;
        let (gzip, brotli) =
            compress(&bytes).with_context(|| format!("Compress {}", path.display()))?;
        for (coding, encoded) in [("gz", &gzip), ("br", &brotli)] {
            if encoded.len() < bytes.len() {
                fs::write(
                    path.with_extension(format!("{extension}.{coding}")),
                    encoded,
                )?;
            }
        }
        if matches!(extension, "js" | "wasm") {
            println!(
                "{}: {} bytes raw, {} bytes gzip, {} bytes Brotli.",
                path.file_name().unwrap().to_string_lossy(),
                bytes.len(),
                gzip.len(),
                brotli.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn compression_is_lossless_and_reproducible() {
        let bytes = include_bytes!("../../app/host.js");
        let first = compress(bytes).unwrap();
        assert_eq!(first, compress(bytes).unwrap());
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&first.0[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, bytes);
        decoded.clear();
        brotli::BrotliDecompress(&mut &first.1[..], &mut decoded).unwrap();
        assert_eq!(decoded, bytes);
        assert!(first.0.len() < bytes.len());
        assert!(first.1.len() < first.0.len());
    }
}
