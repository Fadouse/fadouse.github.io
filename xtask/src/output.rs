use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde_json::json;
use sha2::{Digest, Sha256};
use shared::{Catalog, page_metadata, tag_path};

use crate::{
    content::{CompiledPost, Content},
    markdown::escape,
    render,
};

fn hashed_index(dist: &Path, entries: &[shared::search::SearchEntry]) -> Result<String> {
    let bytes = shared::search::encode_index(entries);
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let url = format!("/assets/search-{}.bin", &hash[..16]);
    fs::write(dist.join(url.trim_start_matches('/')), bytes)?;
    Ok(url)
}

fn page_shell(
    template: &str,
    catalog: &Catalog,
    posts: &[CompiledPost],
    path: &str,
    math_assets: Option<&crate::math::assets::Assets>,
) -> String {
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
    let mut structured = if let Some(post) = catalog.posts.iter().find(|post| post.path() == path) {
        if let Some(assets) = math_assets {
            for font in &posts
                .iter()
                .find(|p| p.summary.path() == path)
                .unwrap()
                .math_fonts
            {
                head.push_str(&format!("<link data-page-meta rel=\"preload\" as=\"font\" type=\"font/woff2\" href=\"{}\" crossorigin>",assets.fonts[font]));
            }
        }
        head.push_str(&format!(
            "<meta data-page-meta property=\"article:published_time\" content=\"{}T00:00:00Z\">",
            post.date
        ));
        if let Some(date) = &post.updated {
            head.push_str(&format!("<meta data-page-meta property=\"article:modified_time\" content=\"{date}T00:00:00Z\">"));
        }
        let mut value = json!({"@context":"https://schema.org", "@type":"BlogPosting", "headline":post.title, "description":post.description, "url":metadata.canonical, "mainEntityOfPage":{"@type":"WebPage","@id":metadata.canonical}, "datePublished":post.date, "dateModified":post.updated.as_ref().unwrap_or(&post.date)});
        if let Some(lang) = &post.lang {
            value["inLanguage"] = json!(lang);
        }
        if let Some(author) = catalog
            .site
            .author
            .as_ref()
            .filter(|name| !name.trim().is_empty())
        {
            value["author"] =
                json!({"@type":"Person","name":author,"url":format!("{}/about/",catalog.site.url)});
        }
        value
    } else {
        json!({"@context":"https://schema.org", "@type":if path == "/" { "WebSite" } else { "CollectionPage" }, "name":metadata.title, "description":metadata.description, "url":metadata.canonical})
    };
    if path == "/about/" {
        structured["@type"] = json!("AboutPage");
    }
    head.push_str(&format!("<meta data-page-meta property=\"og:site_name\" content=\"{}\"><script data-page-meta type=\"application/ld+json\">{}</script>", escape(&catalog.site.title), structured.to_string().replace('<', "\\u003c")));
    template
        .replace("</head>", &format!("{head}</head>"))
        .replace(
            "__BLOG_CONTENT__",
            &render::frame(catalog, path, &render::page(catalog, posts, path)),
        )
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
    let search: Vec<_> = content
        .posts
        .iter()
        .map(|post| shared::search::SearchEntry::from(&post.search))
        .collect();
    let search_url = hashed_index(dist, &search)?;
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
    let mut template = fs::read_to_string(dist.join("index.html"))?;
    template = crate::assets::build(root, dist, template)?;
    let used_fonts = content
        .posts
        .iter()
        .flat_map(|p| p.math_fonts.iter().cloned())
        .collect();
    let math_assets = if content.posts.iter().any(|post| post.has_math) {
        Some(crate::math::assets::publish(root, dist, &used_fonts)?)
    } else {
        None
    };
    if let Some(assets) = &math_assets {
        template = crate::assets::append_css(dist, &template, &assets.css)?;
    }
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
        write_route(
            dist,
            route,
            &page_shell(
                &template,
                &catalog,
                &content.posts,
                route,
                math_assets.as_ref(),
            ),
        )?;
    }
    fs::write(
        dist.join("404.html"),
        page_shell(
            &template,
            &catalog,
            &content.posts,
            "/404/",
            math_assets.as_ref(),
        ),
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
        let modified = catalog
            .posts
            .iter()
            .find(|post| post.path() == *route)
            .map(|post| {
                format!(
                    "<lastmod>{}</lastmod>",
                    post.updated.as_ref().unwrap_or(&post.date)
                )
            })
            .unwrap_or_default();
        sitemap.push_str(&format!(
            "<url><loc>{}</loc>{modified}</url>",
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
        "/*\n  X-Robots-Tag: noindex\n\n"
    } else {
        ""
    };
    fs::write(
        dist.join("_headers"),
        format!(
            "{preview_header}/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n"
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
