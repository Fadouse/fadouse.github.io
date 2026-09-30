use std::fmt::Write;

use shared::{Catalog, Heading, PostSummary, tag_path};

use crate::{content::CompiledPost, markdown::escape};

pub fn frame(catalog: &Catalog, path: &str, body: &str) -> String {
    let home = path == "/";
    let brand_tag = if home { "h1" } else { "div" };
    let mut navigation = String::new();
    for (href, label) in [
        ("/", "Writing"),
        ("/archive/", "Archive"),
        ("/tags/", "Tags"),
        ("/about/", "About"),
        ("/search/", "Search"),
    ] {
        let active = if href != "/" && path.starts_with(href) {
            " aria-current=\"page\""
        } else {
            ""
        };
        let extra = if href == "/search/" {
            " class=\"search-link\" aria-keyshortcuts=\"Meta+K Control+K\""
        } else {
            ""
        };
        let hint = if href == "/search/" {
            "<kbd class=\"shortcut\" aria-hidden=\"true\">⌘K</kbd>"
        } else {
            ""
        };
        write!(
            navigation,
            "<a href=\"{href}\" data-nav{active}{extra}>{label}{hint}</a>"
        )
        .unwrap();
    }
    format!(
        r##"<a class="skip-link" href="#main-content">Skip to content</a>
<div class="site-shell" data-search-url="{search_url}">
<header class="site-header{home_class}"><{brand_tag} id="brand-heading"><a href="/" class="brand"{brand_current}>{title}</a></{brand_tag}>
<nav class="navigation" aria-label="Main navigation">{navigation}</nav></header>
<main class="page" id="main-content" tabindex="-1"><div id="page-content" data-page="{path}">{body}</div></main>
<footer class="site-footer"><div class="footer-links"><span>{title}</span><a href="/feed.xml">RSS ↗</a></div>
<div class="theme-picker" role="group" aria-label="Color theme"><button type="button" data-theme-choice="system" aria-pressed="true">System</button><button type="button" data-theme-choice="light" aria-pressed="false">Light</button><button type="button" data-theme-choice="dark" aria-pressed="false">Dark</button></div></footer>
</div><p class="sr-only" id="copy-status" aria-live="polite"></p><p class="sr-only" id="navigation-status" role="status"></p><template id="page-error"><div class="error-state" role="alert"><h1>Unable to load this page.</h1><p>Check your connection and try again.</p><button type="button" data-retry>Retry ↗</button></div></template>"##,
        search_url = escape(&catalog.search_url),
        home_class = if home { " home-header" } else { "" },
        brand_current = if home { " aria-current=\"page\"" } else { "" },
        title = escape(&catalog.site.title),
        path = escape(path),
    )
}

fn heading(title: &str, detail: &str) -> String {
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", escape(detail))
    };
    format!(
        "<div class=\"section-heading\"><h1 dir=\"auto\">{}</h1>{detail}</div>",
        escape(title)
    )
}

fn count(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

fn tag_label(tag: &str) -> String {
    format!(
        "<span class=\"tag-prefix\" aria-hidden=\"true\">#</span><span dir=\"auto\">{}</span>",
        escape(tag)
    )
}

fn tags(tags: &[String]) -> String {
    let mut html = "<div class=\"post-tags\">".to_owned();
    for tag in tags {
        write!(html, "<a href=\"{}\">{}</a>", tag_path(tag), tag_label(tag)).unwrap();
    }
    html.push_str("</div>");
    html
}

fn post_list(posts: &[&PostSummary]) -> String {
    if posts.is_empty() {
        return "<p class=\"empty-state\">No posts yet.</p>".into();
    }
    let mut html = "<ul class=\"post-list\">".to_owned();
    for post in posts {
        write!(html, r#"<li class="post-row"><time class="post-date" datetime="{date}">{date}</time><article><h2 class="post-title" dir="auto"><a href="{path}">{title}</a></h2><p class="post-description" dir="auto">{description}</p>{tags}</article></li>"#,
            date = post.date, path = post.path(), title = escape(&post.title), description = escape(&post.description), tags = tags(&post.tags)).unwrap();
    }
    html.push_str("</ul>");
    html
}

fn contents(headings: &[Heading]) -> String {
    let mut html = "<ul>".to_owned();
    for heading in headings {
        write!(
            html,
            "<li{}><a href=\"#{}\">{}</a></li>",
            if heading.level > 2 {
                " class=\"nested-heading\""
            } else {
                ""
            },
            escape(&heading.id),
            escape(&heading.text)
        )
        .unwrap();
    }
    html.push_str("</ul>");
    html
}

fn article(post: &CompiledPost, posts: &[CompiledPost], index: usize) -> String {
    let summary = &post.summary;
    let updated = summary
        .updated
        .as_ref()
        .map(|date| format!(" · Updated <time datetime=\"{date}\">{date}</time>"))
        .unwrap_or_default();
    let mut html = format!(
        r#"<header class="article-header"><p class="muted"><time datetime="{date}">{date}</time>{updated}</p><h1 dir="auto">{title}</h1>{tags}</header><div class="article-layout">"#,
        date = summary.date,
        title = escape(&summary.title),
        tags = tags(&summary.tags)
    );
    let toc = contents(&post.content.headings);
    let has_headings = !post.content.headings.is_empty();
    if has_headings {
        write!(html, "<aside class=\"toc desktop-toc\" aria-label=\"On this page\"><h2 class=\"toc-title\">On this page</h2>{toc}</aside>").unwrap();
    }
    html.push_str("<div class=\"article-body\">");
    if has_headings {
        write!(
            html,
            "<details class=\"toc mobile-toc\"><summary>On this page</summary>{toc}</details>"
        )
        .unwrap();
    }
    write!(
        html,
        "<article class=\"prose\" lang=\"{}\" dir=\"auto\">{}</article></div></div>",
        escape(summary.lang.as_deref().unwrap_or("und")),
        post.content.html
    )
    .unwrap();
    if posts.len() > 1 {
        html.push_str("<nav class=\"post-pagination\" aria-label=\"More articles\"><div>");
        if let Some(older) = posts.get(index + 1) {
            write!(
                html,
                "<a href=\"{}\"><span class=\"muted\">← Older</span><span>{}</span></a>",
                older.summary.path(),
                escape(&older.summary.title)
            )
            .unwrap();
        }
        html.push_str("</div><div>");
        if let Some(newer) = index.checked_sub(1).and_then(|index| posts.get(index)) {
            write!(
                html,
                "<a href=\"{}\"><span class=\"muted\">Newer →</span><span>{}</span></a>",
                newer.summary.path(),
                escape(&newer.summary.title)
            )
            .unwrap();
        }
        html.push_str("</div></nav>");
    }
    html
}

pub fn page(catalog: &Catalog, posts: &[CompiledPost], path: &str) -> String {
    let all: Vec<_> = catalog.posts.iter().collect();
    match path {
        "/" => {
            let intro = if catalog.site.intro.is_empty() {
                String::new()
            } else {
                format!(
                    "<p class=\"introduction\">{}</p>",
                    escape(&catalog.site.intro)
                )
            };
            format!(
                "{intro}<section aria-labelledby=\"writing-heading\"><div class=\"section-heading\"><h2 id=\"writing-heading\">Writing</h2></div>{}</section>",
                post_list(&all[..all.len().min(12)])
            )
        }
        "/archive/" => {
            let mut html = heading("Archive", &count(all.len(), "post"));
            if all.is_empty() {
                html.push_str(&post_list(&[]));
            }
            let mut start = 0;
            while start < all.len() {
                let year = &all[start].date[..4];
                let end = start
                    + all[start..]
                        .iter()
                        .take_while(|post| post.date.starts_with(year))
                        .count();
                write!(html, "<section class=\"year-group\"><h2 class=\"year-heading\">{year}</h2>{}</section>", post_list(&all[start..end])).unwrap();
                start = end;
            }
            html
        }
        "/tags/" => {
            let mut html = heading("Tags", &count(catalog.tags.len(), "tag"));
            if catalog.tags.is_empty() {
                html.push_str("<p class=\"empty-state\">No tags yet.</p>");
            }
            html.push_str("<ul class=\"tag-index\">");
            for tag in &catalog.tags {
                write!(
                    html,
                    "<li><a href=\"{}\"><span>{}</span><span class=\"muted\">{}</span></a></li>",
                    tag_path(&tag.name),
                    tag_label(&tag.name),
                    count(tag.count, "post")
                )
                .unwrap();
            }
            html.push_str("</ul>");
            html
        }
        "/about/" => format!(
            "{}<p class=\"{}\">{}</p>",
            heading("About", ""),
            if catalog.site.about.is_empty() {
                "empty-state"
            } else {
                "about-copy"
            },
            if catalog.site.about.is_empty() {
                "Nothing here yet.".into()
            } else {
                escape(&catalog.site.about)
            }
        ),
        "/search/" => format!(
            r#"{}<form class="search-form" role="search" action="/search/" method="get"><label for="search-input">Search titles, tags, and articles.</label><div class="search-field"><input id="search-input" name="q" type="search" autocomplete="off" spellcheck="false" placeholder="Type to search…"><button type="submit">Search →</button></div></form><div id="search-results"><p class="muted" role="status">Start with a word or phrase.</p></div><noscript><p>Enable JavaScript to search.</p></noscript><template id="search-layout"><p class="muted" role="status"></p><div class="search-results"></div></template><template id="search-entry"><article><h2 class="post-title" dir="auto"><a></a></h2><p dir="auto"></p></article></template>"#,
            heading("Search", "")
        ),
        _ => {
            if let Some((index, post)) = posts
                .iter()
                .enumerate()
                .find(|(_, post)| post.summary.path() == path)
            {
                article(post, posts, index)
            } else if let Some(tag) = catalog.tags.iter().find(|tag| tag_path(&tag.name) == path) {
                let matching: Vec<_> = all
                    .into_iter()
                    .filter(|post| post.tags.contains(&tag.name))
                    .collect();
                format!(
                    "{}{}",
                    heading(&tag.name, &count(matching.len(), "post")),
                    post_list(&matching)
                )
            } else {
                format!(
                    "{}<p>The page you requested does not exist.</p><a href=\"/\">Back to writing →</a>",
                    heading("Page not found", "404")
                )
            }
        }
    }
}
