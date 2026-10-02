// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use tiny_http::{Header, Method, Request, Response, ResponseBox, Server};

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).unwrap()
}

fn quality(accept: &str, coding: &str) -> Option<f32> {
    accept.split(',').find_map(|entry| {
        let mut parts = entry.trim().split(';');
        if !parts.next()?.trim().eq_ignore_ascii_case(coding) {
            return None;
        }
        Some(
            parts
                .find_map(|part| part.trim().strip_prefix("q="))
                .map_or(1.0, |value| {
                    value
                        .parse::<f32>()
                        .ok()
                        .filter(|q| (0.0..=1.0).contains(q))
                        .unwrap_or(0.0)
                }),
        )
    })
}

fn choose_encoding(accept: &str, brotli: bool, gzip: bool) -> Option<&'static str> {
    let mut best = (None, 0.0);
    for (coding, available) in [("br", brotli), ("gzip", gzip)] {
        let q = quality(accept, coding)
            .or_else(|| quality(accept, "*"))
            .unwrap_or(0.0);
        if available && q > best.1 {
            best = (Some(coding), q);
        }
    }
    if quality(accept, "identity").is_some_and(|q| q > best.1) {
        None
    } else {
        best.0
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut encoded = path.as_os_str().to_owned();
    encoded.push(suffix);
    PathBuf::from(encoded)
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "woff2" => "font/woff2",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn response(request: &Request, dist: &Path, redirects: &str) -> Result<ResponseBox> {
    if !matches!(request.method(), Method::Get | Method::Head) {
        return Ok(Response::empty(405)
            .with_header(header("Allow", "GET, HEAD"))
            .boxed());
    }
    let (url, query) = request.url().split_once('?').unwrap_or((request.url(), ""));
    for line in redirects.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() == 3 && url == parts[0] {
            let location = format!(
                "{}{}{}",
                parts[1],
                if query.is_empty() { "" } else { "?" },
                query
            );
            return Ok(Response::empty(parts[2].parse::<u16>()?)
                .with_header(header("Location", &location))
                .with_header(header("Cache-Control", "no-cache"))
                .boxed());
        }
    }
    let decoded = percent_encoding::percent_decode_str(url).decode_utf8()?;
    let path = dist.join(decoded.trim_start_matches('/'));
    let mut path = path
        .canonicalize()
        .ok()
        .filter(|path| path.starts_with(dist));
    if let Some(directory) = path.as_ref().filter(|path| path.is_dir()) {
        if !url.ends_with('/') {
            let location = format!("{url}/{}{query}", if query.is_empty() { "" } else { "?" });
            return Ok(Response::empty(301)
                .with_header(header("Location", &location))
                .boxed());
        }
        path = directory
            .join("index.html")
            .canonicalize()
            .ok()
            .filter(|path| path.starts_with(dist));
    }
    let (path, status) = if let Some(path) = path.filter(|path| path.is_file()) {
        (path, 200)
    } else {
        (dist.join("404.html"), 404)
    };
    let accept = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Accept-Encoding"))
        .map_or("", |h| h.value.as_str());
    let brotli = sidecar(&path, ".br");
    let gzip = sidecar(&path, ".gz");
    let available = (brotli.is_file(), gzip.is_file());
    let coding = choose_encoding(accept, available.0, available.1);
    let identity = quality(accept, "identity").unwrap_or(if quality(accept, "*") == Some(0.0) {
        0.0
    } else {
        1.0
    });
    if coding.is_none() && identity == 0.0 {
        return Ok(Response::empty(406)
            .with_header(header("Vary", "Accept-Encoding"))
            .boxed());
    }
    let file = fs::File::open(match coding {
        Some("br") => &brotli,
        Some("gzip") => &gzip,
        _ => &path,
    })?;
    let mut response = Response::from_file(file)
        .with_status_code(status)
        .with_header(header("Content-Type", content_type(&path)))
        .with_header(header(
            "Cache-Control",
            if status == 200 && url.starts_with("/assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            },
        ));
    if available.0 || available.1 {
        response.add_header(header("Vary", "Accept-Encoding"));
    }
    if let Some(coding) = coding {
        response.add_header(header("Content-Encoding", coding));
    }
    Ok(response.boxed())
}

pub fn run(dist: &Path, host: IpAddr, port: u16) -> Result<()> {
    let dist = dist
        .canonicalize()
        .context("Build the release site before serving it")?;
    ensure!(
        dist.join("index.html").is_file(),
        "Run cargo xtask build first"
    );
    let redirects = fs::read_to_string(dist.join("_redirects"))?;
    let server = Server::http((host, port)).map_err(|error| anyhow::anyhow!("{error}"))?;
    println!("Release preview: http://{}", server.server_addr());
    for request in server.incoming_requests() {
        let result = match response(&request, &dist, &redirects) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("Unable to serve {}: {error}", request.url());
                Response::empty(500).boxed()
            }
        };
        // Browsers may cancel a request when navigating away.
        let _ = request.respond(result);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_respects_preferences_exclusions_and_availability() {
        for (accept, br, gzip, expected) in [
            ("gzip, deflate, br", true, true, Some("br")),
            ("br;q=0, gzip", true, true, Some("gzip")),
            ("br;q=0.5, gzip;q=0.8", true, true, Some("gzip")),
            ("br", false, true, None),
            ("*;q=0.8", true, true, Some("br")),
            ("br;q=0.5, identity;q=1", true, true, None),
            ("br;q=0, gzip;q=0", true, true, None),
            ("", true, true, None),
        ] {
            assert_eq!(choose_encoding(accept, br, gzip), expected, "{accept}");
        }
    }
}
