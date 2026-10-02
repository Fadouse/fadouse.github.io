// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

mod assets;
mod content;
mod highlight;
mod markdown;
mod math;
mod output;
mod render;

use std::{
    env, fs,
    net::{IpAddr, TcpListener},
    path::PathBuf,
    process::Command,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use shared::SiteConfig;

#[derive(Parser)]
#[command(about = "Build and develop the blog")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Start the development server with automatic rebuilding.
    Dev {
        /// Use an available port by default.
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        host: IpAddr,
    },
    /// Build the static site for Cloudflare Pages.
    Build {
        /// Public origin; may also be set in site.toml or CF_PAGES_URL.
        #[arg(long, env = "SITE_URL")]
        site_url: Option<String>,
        /// Prevent search engines from indexing this deployment.
        #[arg(long)]
        preview: bool,
    },
    #[command(hide = true)]
    Content {
        #[arg(long, env = "TRUNK_STAGING_DIR")]
        dist: PathBuf,
        #[arg(long, env = "SITE_URL")]
        site_url: String,
        #[arg(long, env = "SITE_PREVIEW")]
        preview: bool,
    },
}

fn main() -> Result<()> {
    // Cargo resolves this path separately in each checkout and on each platform.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    let mut trunk = Command::new("trunk");
    trunk.current_dir(&root).env("NO_COLOR", "true");
    match Cli::parse().command {
        Task::Dev { port, host } => {
            let address = TcpListener::bind((host, port))?.local_addr()?;
            trunk
                .args(["serve", "--locked", "--no-spa", "true", "--address"])
                .arg(host.to_string())
                .arg("--port")
                .arg(address.port().to_string())
                .env("SITE_URL", format!("http://{address}"))
                .env("SITE_PREVIEW", "true");
            println!("Development server: http://{address}");
        }
        Task::Build { site_url, preview } => {
            let site: SiteConfig = toml::from_str(&fs::read_to_string(root.join("site.toml"))?)?;
            let origin = site_url
                .or_else(|| env::var("CF_PAGES_URL").ok())
                .unwrap_or(site.url);
            ensure!(
                !origin.is_empty(),
                "Set --site-url, SITE_URL, or url in site.toml before building"
            );
            let origin =
                url::Url::parse(&origin).context("Site URL must be an absolute HTTP(S) origin")?;
            ensure!(
                matches!(origin.scheme(), "http" | "https")
                    && origin.host_str().is_some()
                    && origin.path() == "/"
                    && origin.query().is_none()
                    && origin.fragment().is_none(),
                "Site URL must be an HTTP(S) origin without a path, query, or fragment"
            );
            let production = env::var("PRODUCTION_BRANCH").unwrap_or_else(|_| "main".into());
            let preview =
                preview || env::var("CF_PAGES_BRANCH").is_ok_and(|branch| branch != production);
            trunk
                .args(["build", "--release", "--locked"])
                .env("SITE_URL", origin.as_str().trim_end_matches('/'))
                .env("SITE_PREVIEW", preview.to_string());
        }
        Task::Content {
            dist,
            site_url,
            preview,
        } => {
            return output::finish(&root, &dist, content::compile(&root)?, &site_url, preview);
        }
    }
    let status = trunk
        .status()
        .context("Install Trunk with: cargo install trunk --version 0.21.14 --locked")?;
    ensure!(status.success(), "Trunk exited with {status}");
    Ok(())
}
