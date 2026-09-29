use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::Serialize;
use sha2::{Digest, Sha256};
use shared::{Catalog, page_metadata, tag_path};

use crate::{content::Content, markdown::escape};

fn hashed_json(dist: &Path, name: &str, value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let url = format!("/assets/{name}-{}.json", &hash[..16]);
    fs::write(dist.join(url.trim_start_matches('/')), bytes)?;
    Ok(url)
}

fn page_shell(template: &str, catalog: &Catalog, path: &str) -> String {
    let metadata = page_metadata(catalog, path);
    let robots = if metadata.noindex {
        "noindex,follow"
    } else {
        "index,follow"
    };
    let mut head = format!(
        "<title data-page-meta>{title}</title>\n<meta data-page-meta name=\"description\" content=\"{description}\">\n<link data-page-meta rel=\"canonical\" href=\"{canonical}\">\n<meta data-page-meta property=\"og:title\" content=\"{title}\">\n<meta data-page-meta property=\"og:description\" content=\"{description}\">\n<meta data-page-meta property=\"og:url\" content=\"{canonical}\">\n<meta data-page-meta property=\"og:type\" content=\"{kind}\">\n<meta data-page-meta name=\"twitter:card\" content=\"summary\">\n<meta data-page-meta name=\"twitter:title\" content=\"{title}\">\n<meta data-page-meta name=\"twitter:description\" content=\"{description}\">\n<meta data-page-meta name=\"robots\" content=\"{robots}\">\n",
        title = escape(&metadata.title),
        description = escape(&metadata.description),
        canonical = escape(&metadata.canonical),
        kind = if metadata.article {
            "article"
        } else {
            "website"
        },
    );
    if let Some(post) = catalog.posts.iter().find(|post| post.path() == path) {
        head.push_str(&format!(
            "<link rel=\"preload\" as=\"fetch\" href=\"{}\" crossorigin>\n",
            post.content_url
        ));
    }
    template.replace("</head>", &format!("{head}</head>"))
}

fn write_route(dist: &Path, path: &str, html: &str) -> Result<()> {
    let path = percent_encoding::percent_decode_str(path).decode_utf8()?;
    let directory = dist.join(path.trim_matches('/'));
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("index.html"), html)?;
    Ok(())
}

fn copy_media(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_media(&entry.path(), &destination.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), destination.join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn finish(
    root: &Path,
    dist: &Path,
    mut content: Content,
    site_url: &str,
    preview: bool,
) -> Result<()> {
    fs::create_dir_all(dist.join("assets"))?;
    content.site.url = site_url.trim_end_matches('/').to_owned();
    for post in &mut content.posts {
        post.summary.content_url =
            hashed_json(dist, &format!("post-{}", post.summary.slug), &post.content)?;
    }
    let search: Vec<_> = content.posts.iter().map(|post| &post.search).collect();
    let search_url = hashed_json(dist, "search", &search)?;
    let catalog = Catalog {
        site: content.site,
        posts: content
            .posts
            .iter()
            .map(|post| post.summary.clone())
            .collect(),
        tags: content.tags,
        search_url,
        preview,
    };
    let catalog_url = hashed_json(dist, "catalog", &catalog)?;
    let template = fs::read_to_string(dist.join("index.html"))?
        .replace("/catalog.json", &catalog_url)
        .replace(
            "</head>",
            &format!(
                "<link rel=\"preload\" as=\"fetch\" href=\"{catalog_url}\" crossorigin></head>"
            ),
        );
    let mut routes = vec![
        "/".to_owned(),
        "/archive/".into(),
        "/tags/".into(),
        "/about/".into(),
        "/search/".into(),
    ];
    routes.extend(catalog.posts.iter().map(|post| post.path()));
    routes.extend(catalog.tags.iter().map(|tag| tag_path(&tag.name)));
    for route in &routes {
        write_route(dist, route, &page_shell(&template, &catalog, route))?;
    }
    fs::write(
        dist.join("404.html"),
        page_shell(&template, &catalog, "/404/"),
    )?;

    let mut feed = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\"><channel><title>{}</title><link>{}/</link><description>{}</description><atom:link href=\"{}/feed.xml\" rel=\"self\" type=\"application/rss+xml\"/>",
        escape(&catalog.site.title),
        escape(site_url),
        escape(&catalog.site.description),
        escape(site_url)
    );
    for post in &catalog.posts {
        let date = NaiveDate::parse_from_str(&post.date, "%Y-%m-%d")?
            .and_hms_opt(0, 0, 0)
            .context("Invalid article date")?
            .and_utc()
            .to_rfc2822();
        let url = format!("{site_url}{}", post.path());
        feed.push_str(&format!("<item><title>{}</title><link>{}</link><guid>{}</guid><pubDate>{}</pubDate><description>{}</description></item>", escape(&post.title), escape(&url), escape(&url), date, escape(&post.description)));
    }
    feed.push_str("</channel></rss>");
    fs::write(dist.join("feed.xml"), feed)?;
    let mut sitemap = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">".to_owned();
    for route in routes.iter().filter(|route| route.as_str() != "/search/") {
        sitemap.push_str(&format!(
            "<url><loc>{}</loc></url>",
            escape(&format!("{site_url}{route}"))
        ));
    }
    sitemap.push_str("</urlset>");
    fs::write(dist.join("sitemap.xml"), sitemap)?;
    fs::write(
        dist.join("robots.txt"),
        if preview {
            "User-agent: *\nDisallow: /\n".to_owned()
        } else {
            format!("User-agent: *\nAllow: /\nSitemap: {site_url}/sitemap.xml\n")
        },
    )?;
    let preview_header = if preview {
        "  X-Robots-Tag: noindex\n"
    } else {
        ""
    };
    fs::write(
        dist.join("_headers"),
        format!(
            "/*\n  Cache-Control: public, max-age=0, must-revalidate\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n{preview_header}\n/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n"
        ),
    )?;
    copy_media(&root.join("content/media"), &dist.join("media"))?;

    println!(
        "Built {} articles and {} page entries.",
        catalog.posts.len(),
        routes.len()
    );
    Ok(())
}
