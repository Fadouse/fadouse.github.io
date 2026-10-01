use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use chrono::NaiveDate;
use serde::Deserialize;
use shared::{PostContent, PostSummary, SearchDocument, SiteConfig, TagSummary};

use crate::markdown;

#[derive(Deserialize)]
struct FrontMatter {
    title: String,
    date: DateInput,
    slug: String,
    updated: Option<DateInput>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
    lang: Option<String>,
    #[serde(default)]
    draft: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DateInput {
    Text(String),
    Date(toml::value::Datetime),
}

impl DateInput {
    fn validate(&self) -> Result<String> {
        let text = match self {
            Self::Text(value) => value.clone(),
            Self::Date(value) => value.to_string(),
        };
        NaiveDate::parse_from_str(&text, "%Y-%m-%d")
            .with_context(|| format!("Invalid publication date: {text}; use YYYY-MM-DD"))?;
        Ok(text)
    }
}

pub struct CompiledPost {
    pub summary: PostSummary,
    pub content: PostContent,
    pub search: SearchDocument,
    pub math_fonts: std::collections::BTreeSet<String>,
    pub has_math: bool,
}

pub struct Content {
    pub site: SiteConfig,
    pub posts: Vec<CompiledPost>,
    pub tags: Vec<TagSummary>,
}

fn parse_post(source: &str, media_dir: &Path) -> Result<Option<CompiledPost>> {
    let normalized = source.replace("\r\n", "\n");
    let Some(rest) = normalized.strip_prefix("+++\n") else {
        bail!("Article must start with TOML front matter delimited by +++");
    };
    let (front_matter, body) = rest
        .split_once("\n+++")
        .context("Missing closing +++ front matter delimiter")?;
    let front: FrontMatter =
        toml::from_str(front_matter).context("Invalid article front matter")?;
    if front.draft {
        return Ok(None);
    }
    ensure!(!front.title.trim().is_empty(), "Article title is required");
    ensure!(
        !front.slug.is_empty()
            && front
                .slug
                .chars()
                .all(|character| character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '-'),
        "Article slug must use lowercase ASCII letters, digits, and hyphens"
    );
    let date = front.date.validate()?;
    let updated = front
        .updated
        .as_ref()
        .map(DateInput::validate)
        .transpose()?;
    let rendered = markdown::render(body, media_dir)?;
    let description = if front.description.is_empty() {
        rendered.text.chars().take(160).collect()
    } else {
        front.description
    };
    let mut tags = front.tags;
    for tag in &mut tags {
        *tag = tag.trim().to_owned();
        ensure!(
            !tag.is_empty() && tag != "." && tag != ".." && !tag.contains(['/', '\\']),
            "Tag names cannot contain path separators"
        );
    }
    tags.sort();
    tags.dedup();
    let search = SearchDocument {
        slug: front.slug.clone(),
        title: front.title.clone(),
        tags: tags.join(" "),
        description: description.clone(),
        text: rendered.text,
    };
    Ok(Some(CompiledPost {
        summary: PostSummary {
            title: front.title,
            slug: front.slug,
            date,
            updated,
            description,
            tags,
            lang: front.lang,
        },
        content: rendered.content,
        search,
        math_fonts: rendered.math_fonts,
        has_math: rendered.has_math,
    }))
}

pub fn compile(root: &Path) -> Result<Content> {
    let site: SiteConfig = toml::from_str(&fs::read_to_string(root.join("site.toml"))?)?;
    ensure!(!site.title.trim().is_empty(), "Site title is required");
    let posts_dir = root.join("content/posts");
    let mut posts = Vec::new();
    let mut slugs = HashSet::new();
    if posts_dir.is_dir() {
        for entry in fs::read_dir(posts_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == "md") {
                let source = fs::read_to_string(&path)?;
                if let Some(post) = parse_post(&source, &root.join("content/media"))
                    .with_context(|| format!("Compile {}", path.display()))?
                {
                    ensure!(
                        slugs.insert(post.summary.slug.clone()),
                        "Duplicate article slug: {}",
                        post.summary.slug
                    );
                    posts.push(post);
                }
            }
        }
    }
    posts.sort_by(|left, right| {
        right
            .summary
            .date
            .cmp(&left.summary.date)
            .then(left.summary.slug.cmp(&right.summary.slug))
    });
    let mut tags = BTreeMap::new();
    for post in &posts {
        for tag in &post.summary.tags {
            *tags.entry(tag.clone()).or_insert(0) += 1;
        }
    }
    Ok(Content {
        site,
        posts,
        tags: tags
            .into_iter()
            .map(|(name, count)| TagSummary { name, count })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_pipeline_excludes_drafts_and_rejects_duplicate_slugs() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(
            root.join("site.toml"),
            "title='Test'\ndescription='Test site'",
        )
        .unwrap();
        fs::create_dir_all(root.join("content/posts")).unwrap();
        let article =
            "+++\ntitle='Hello'\ndate=2026-09-29\nslug='hello'\ntags=['Rust']\n+++\n\nHello world.";
        fs::write(root.join("content/posts/hello.md"), article).unwrap();
        fs::write(
            root.join("content/posts/draft.md"),
            article.replace("tags=['Rust']", "draft=true"),
        )
        .unwrap();
        let content = compile(root).unwrap();
        assert_eq!(content.posts.len(), 1);
        assert_eq!(content.tags[0].count, 1);
        fs::write(root.join("content/posts/copy.md"), article).unwrap();
        assert!(
            compile(root)
                .err()
                .unwrap()
                .to_string()
                .contains("Duplicate")
        );
    }
}
