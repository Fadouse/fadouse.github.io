use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

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
    pub content_url: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bootstrap {
    pub catalog_url: String,
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
        noindex: catalog.preview || !found || path == "/search/",
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

pub fn normalize(text: &str) -> String {
    text.nfkc().flat_map(char::to_lowercase).collect()
}

pub struct SearchIndex {
    documents: Vec<SearchDocument>,
    normalized: Vec<[String; 4]>,
}

pub struct SearchHit<'a> {
    pub document: &'a SearchDocument,
    pub excerpt: String,
}

impl SearchIndex {
    pub fn new(documents: Vec<SearchDocument>) -> Self {
        let normalized = documents
            .iter()
            .map(|document| {
                [
                    normalize(&document.title),
                    normalize(&document.tags),
                    normalize(&document.description),
                    normalize(&document.text),
                ]
            })
            .collect();
        Self {
            documents,
            normalized,
        }
    }

    pub fn search(&self, query: &str) -> Vec<SearchHit<'_>> {
        let normalized = normalize(query);
        let terms: Vec<&str> = normalized.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }
        let mut ranked: Vec<_> = self
            .documents
            .iter()
            .zip(&self.normalized)
            .filter_map(|(document, fields)| {
                let mut score = 0;
                for term in &terms {
                    let weight = fields
                        .iter()
                        .zip([8, 4, 2, 1])
                        .filter(|(field, _)| field.contains(term))
                        .map(|(_, weight)| weight)
                        .sum::<usize>();
                    if weight == 0 {
                        return None;
                    }
                    score += weight;
                }
                Some((score, document))
            })
            .collect();
        // Stable ordering keeps equally relevant posts in publication order.
        ranked.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        ranked
            .into_iter()
            .map(|(_, document)| SearchHit {
                document,
                excerpt: excerpt(&document.text, &terms, 180),
            })
            .collect()
    }
}

fn mapped_text(text: &str) -> (String, Vec<(usize, usize, usize, usize)>) {
    let mut normalized = String::new();
    let mut boundaries = Vec::new();
    for (start, grapheme) in text.grapheme_indices(true) {
        let normalized_start = normalized.len();
        normalized.push_str(&normalize(grapheme));
        boundaries.push((
            normalized_start,
            normalized.len(),
            start,
            start + grapheme.len(),
        ));
    }
    (normalized, boundaries)
}

pub fn highlight_parts(text: &str, query: &str) -> Vec<(String, bool)> {
    let (normalized, boundaries) = mapped_text(text);
    let query = normalize(query);
    let mut ranges = Vec::new();
    for term in query.split_whitespace() {
        for (start, _) in normalized.match_indices(term) {
            let end = start + term.len();
            let first = boundaries.iter().find(|range| range.1 > start);
            let last = boundaries.iter().rfind(|range| range.0 < end);
            if let (Some(first), Some(last)) = (first, last) {
                ranges.push((first.2, last.3));
            }
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    let mut parts = Vec::new();
    let mut cursor = 0;
    for (start, end) in merged {
        if start > cursor {
            parts.push((text[cursor..start].to_owned(), false));
        }
        parts.push((text[start..end].to_owned(), true));
        cursor = end;
    }
    if cursor < text.len() {
        parts.push((text[cursor..].to_owned(), false));
    }
    parts
}

fn excerpt(text: &str, terms: &[&str], limit: usize) -> String {
    let (normalized, boundaries) = mapped_text(text);
    let first_match = terms.iter().filter_map(|term| normalized.find(term)).min();
    let position = first_match
        .and_then(|index| boundaries.iter().position(|range| range.1 > index))
        .unwrap_or(0);
    let start = position.saturating_sub(40);
    let graphemes: Vec<&str> = text.graphemes(true).collect();
    let end = (start + limit).min(graphemes.len());
    format!(
        "{}{}{}",
        if start > 0 { "…" } else { "" },
        graphemes[start..end].concat(),
        if end < graphemes.len() { "…" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_ranks_titles_and_matches_mixed_language() {
        let index = SearchIndex::new(vec![
            SearchDocument {
                slug: "body-match".into(),
                title: "Other notes".into(),
                tags: String::new(),
                description: String::new(),
                text: "Hello 世界 in a paragraph.".into(),
            },
            SearchDocument {
                slug: "title-match".into(),
                title: "Hello 世界".into(),
                tags: String::new(),
                description: String::new(),
                text: "A multilingual greeting.".into(),
            },
        ]);
        let hits = index.search("HELLO 世界");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].document.slug, "title-match");
        assert!(index.search("missing").is_empty());
    }

    #[test]
    fn highlighting_preserves_unicode_and_combining_marks() {
        let text = "Hello 世界, cafe\u{301} 👋";
        let parts = highlight_parts(text, "世界 café");
        assert_eq!(
            parts.iter().map(|part| part.0.as_str()).collect::<String>(),
            text
        );
        assert_eq!(parts.iter().filter(|part| part.1).count(), 2);
    }
}
