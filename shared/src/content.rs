use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct SiteConfig {
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub intro: String,
    #[serde(default)]
    pub about: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PostSummary {
    pub title: String,
    pub slug: String,
    pub date: String,
    pub updated: Option<String>,
    pub description: String,
    pub tags: Vec<String>,
    pub lang: Option<String>,
}

impl PostSummary {
    pub fn path(&self) -> String {
        format!("/posts/{}/", self.slug)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Heading {
    pub id: String,
    pub text: String,
    pub level: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PostContent {
    pub html: String,
    pub headings: Vec<Heading>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TagSummary {
    pub name: String,
    pub count: usize,
}

pub fn tag_path(tag: &str) -> String {
    format!("/tags/{}/", utf8_percent_encode(tag, PATH_SEGMENT))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Catalog {
    pub site: SiteConfig,
    pub posts: Vec<PostSummary>,
    pub tags: Vec<TagSummary>,
    pub search_url: String,
    pub preview: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PageMetadata {
    pub title: String,
    pub description: String,
    pub canonical: String,
    pub article: bool,
    pub noindex: bool,
}

pub fn page_metadata(catalog: &Catalog, path: &str) -> PageMetadata {
    let path = if path == "/" {
        "/".to_owned()
    } else {
        format!("{}/", path.trim_end_matches('/'))
    };
    let decoded = percent_encoding::percent_decode_str(&path).decode_utf8_lossy();
    let post = catalog.posts.iter().find(|post| post.path() == path);
    let tag = catalog
        .tags
        .iter()
        .find(|tag| format!("/tags/{}/", tag.name) == decoded);
    let (label, description, found) = if let Some(post) = post {
        (post.title.clone(), post.description.clone(), true)
    } else if let Some(tag) = tag {
        (
            tag.name.clone(),
            format!("Posts tagged {}.", tag.name),
            true,
        )
    } else {
        let label = match path.as_str() {
            "/" => "",
            "/archive/" => "Archive",
            "/tags/" => "Tags",
            "/search/" => "Search",
            "/about/" => "About",
            _ => "Page not found",
        };
        (
            label.to_owned(),
            catalog.site.description.clone(),
            label != "Page not found",
        )
    };
    PageMetadata {
        title: if label.is_empty() {
            catalog.site.title.clone()
        } else {
            format!("{label} — {}", catalog.site.title)
        },
        description,
        canonical: format!("{}{}", catalog.site.url, path),
        article: post.is_some(),
        noindex: catalog.preview
            || !found
            || path == "/search/"
            || (path == "/about/" && catalog.site.about.trim().is_empty()),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchDocument {
    pub slug: String,
    pub title: String,
    pub tags: String,
    pub description: String,
    pub text: String,
}
