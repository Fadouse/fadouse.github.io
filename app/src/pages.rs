use std::sync::Arc;

use leptos::prelude::*;
use leptos_router::{
    NavigateOptions,
    components::A,
    hooks::{use_navigate, use_params_map, use_query_map},
};
use shared::{PostContent, PostSummary, SearchDocument, SearchIndex, highlight_parts, tag_path};

use crate::{
    browser, catalog,
    components::{ChangingContent, ContentsList, LoadError, Loading, PageHeading, PostList, Tags},
};

pub fn route<V: IntoView>(view: fn() -> V) -> impl Fn() -> V + Clone {
    move || {
        browser::transition_page();
        view()
    }
}

#[component]
pub fn HomePage() -> impl IntoView {
    let catalog = catalog();
    let intro = catalog.site.intro.clone();
    let posts = catalog.posts.iter().take(12).cloned().collect();
    view! {
        {(!intro.is_empty()).then(|| view! { <p class="introduction">{intro}</p> })}
        <PageHeading title="Writing">
            <A href="/archive/" attr:class="section-link">"All posts"<span aria-hidden="true">"→"</span></A>
        </PageHeading>
        <PostList posts />
    }
}

#[component]
pub fn ArchivePage() -> impl IntoView {
    let catalog = catalog();
    let mut groups: Vec<(String, Vec<PostSummary>)> = Vec::new();
    for post in &catalog.posts {
        let year = &post.date[..4];
        if let Some((_, posts)) = groups.last_mut().filter(|(current, _)| current == year) {
            posts.push(post.clone());
        } else {
            groups.push((year.to_owned(), vec![post.clone()]));
        }
    }
    view! {
        <PageHeading title="Archive" detail=count_label(catalog.posts.len(), "post") />
        {groups.is_empty().then(|| view! { <p class="empty-state">"No posts yet."</p> })}
        {groups.into_iter().map(|(year, posts)| view! {
            <section class="year-group"><h2 class="year-heading">{year}</h2><PostList posts /></section>
        }).collect_view()}
    }
}

#[component]
pub fn TagsPage() -> impl IntoView {
    let tags = catalog().tags.clone();
    view! {
        <PageHeading title="Tags" detail=count_label(tags.len(), "tag") />
        {tags.is_empty().then(|| view! { <p class="empty-state">"No tags yet."</p> })}
        <ul class="tag-index">{tags.into_iter().map(|tag| view! {
            <li><A href=tag_path(&tag.name)><span>{tag.name}</span><span class="muted">{count_label(tag.count, "post")}</span></A></li>
        }).collect_view()}</ul>
    }
}

#[component]
pub fn TagPage() -> impl IntoView {
    let catalog = catalog();
    let parameters = use_params_map();
    move || {
        browser::transition_page();
        let tag = parameters.read().get("tag").unwrap_or_default();
        let posts: Vec<_> = catalog
            .posts
            .iter()
            .filter(|post| post.tags.contains(&tag))
            .cloned()
            .collect();
        if posts.is_empty() {
            return view! { <NotFoundPage /> }.into_any();
        }
        view! {
            <PageHeading title=tag detail=count_label(posts.len(), "post") />
            <PostList posts />
        }
        .into_any()
    }
}

#[component]
pub fn AboutPage() -> impl IntoView {
    let about = catalog().site.about.clone();
    view! {
        <PageHeading title="About" />
        {if about.is_empty() {
            view! { <p class="empty-state">"Nothing here yet."</p> }.into_any()
        } else {
            view! { <p class="about-copy">{about}</p> }.into_any()
        }}
    }
}

#[component]
pub fn PostPage() -> impl IntoView {
    let catalog = catalog();
    let parameters = use_params_map();
    let post = Memo::new(move |_| {
        let slug = parameters.read().get("slug").unwrap_or_default();
        catalog.posts.iter().find(|post| post.slug == slug).cloned()
    });
    let content = LocalResource::new(move || async move {
        match post.get() {
            Some(post) => browser::fetch_json::<PostContent>(&post.content_url)
                .await
                .map(Some),
            None => Ok(None),
        }
    });
    Effect::new(move |_| {
        if matches!(content.get(), Some(Ok(Some(_)))) {
            browser::restore_scroll();
            browser::mark("article-rendered");
        }
    });
    move || {
        browser::transition_page();
        match post.get() {
            None => view! { <NotFoundPage /> }.into_any(),
            Some(post) => {
                let lang = post.lang.clone().unwrap_or_else(|| "und".into());
                view! {
                <header class="article-header">
                    <p class="muted"><time datetime=post.date.clone()>{post.date.clone()}</time>
                        {post.updated.clone().map(|date| view! { " · Updated " <time datetime=date.clone()>{date.clone()}</time> })}
                    </p>
                    <h1 dir="auto">{post.title.clone()}</h1>
                    <Tags tags=post.tags.clone() />
                </header>
                <ChangingContent view=move || match content.get() {
                        Some(Ok(Some(content))) => view! { <ArticleContent content lang=lang.clone() /> }.into_any(),
                        Some(Err(_)) => view! { <LoadError /> }.into_any(),
                        _ => view! { <Loading /> }.into_any(),
                    } />
                <PostNavigation slug=post.slug />
            }.into_any()
            }
        }
    }
}

#[component]
fn ArticleContent(content: PostContent, lang: String) -> impl IntoView {
    let headings = content.headings;
    let has_headings = !headings.is_empty();
    let desktop = headings.clone();
    view! {
        <div class="article-layout">
            {has_headings.then(|| view! {
                <aside class="toc desktop-toc" aria-label="On this page">
                    <h2 class="toc-title">"On this page"</h2>
                    <ContentsList headings=desktop />
                </aside>
            })}
            <div class="article-body">
                {has_headings.then(|| view! {
                    <details class="toc mobile-toc"><summary>"On this page"</summary><ContentsList headings /></details>
                })}
                <article class="prose" lang=lang dir="auto" inner_html=content.html on:click=browser::copy_code></article>
            </div>
        </div>
    }
}

#[component]
fn PostNavigation(slug: String) -> impl IntoView {
    let catalog = catalog();
    let index = catalog
        .posts
        .iter()
        .position(|post| post.slug == slug)
        .expect("Published article");
    let older = catalog.posts.get(index + 1).cloned();
    let newer = index
        .checked_sub(1)
        .and_then(|index| catalog.posts.get(index))
        .cloned();
    if older.is_none() && newer.is_none() {
        return ().into_any();
    }
    view! {
        <nav class="post-pagination" aria-label="More articles">
            <div>{older.map(|post| view! { <A href=post.path()><span class="muted">"← Older"</span><span>{post.title}</span></A> })}</div>
            <div>{newer.map(|post| view! { <A href=post.path()><span class="muted">"Newer →"</span><span>{post.title}</span></A> })}</div>
        </nav>
    }.into_any()
}

#[component]
pub fn SearchPage() -> impl IntoView {
    let catalog = catalog();
    let query_map = use_query_map();
    let query = Memo::new(move |_| query_map.read().get("q").unwrap_or_default());
    let input = RwSignal::new(query.get_untracked());
    let composing = RwSignal::new(false);
    let navigate = use_navigate();
    let navigate = Callback::new(move |value: String| {
        let encoded = js_sys::encode_uri_component(value.trim());
        let url = if value.trim().is_empty() {
            "/search/".to_owned()
        } else {
            format!("/search/?q={encoded}")
        };
        navigate(
            &url,
            NavigateOptions {
                replace: true,
                scroll: false,
                ..Default::default()
            },
        );
    });
    Effect::new(move |_| input.set(query.get()));
    let search = LocalResource::new(move || {
        let url = catalog.search_url.clone();
        async move {
            let documents = browser::fetch_json::<Vec<SearchDocument>>(&url).await?;
            Ok::<_, String>(Arc::new(SearchIndex::new(documents)))
        }
    });
    view! {
        <PageHeading title="Search" />
        <form class="search-form" role="search" on:submit=move |event| {
            event.prevent_default();
            navigate.run(input.get_untracked());
        }>
            <label for="search-input">"Search titles, tags, and articles."</label>
            <div class="search-field">
                <input id="search-input" name="q" type="search" autocomplete="off" spellcheck="false"
                    placeholder="Type to search…" prop:value=move || input.get()
                    on:input=move |event| {
                        let value = event_target_value(&event);
                        input.set(value.clone());
                        if !composing.get_untracked() { navigate.run(value); }
                    }
                    on:compositionstart=move |_| composing.set(true)
                    on:compositionend=move |event| {
                        composing.set(false);
                        let value = event_target_value(&event);
                        input.set(value.clone());
                        navigate.run(value);
                    }
                />
                <button type="submit">"Search →"</button>
            </div>
        </form>
        <ChangingContent view=move || match search.get() {
                Some(Ok(index)) => (move || view! {
                    <SearchResults index=Arc::clone(&index) query=query.get() />
                }).into_any(),
                Some(Err(_)) => view! { <LoadError /> }.into_any(),
                None => view! { <Loading /> }.into_any(),
            } />
    }
}

#[component]
fn SearchResults(index: Arc<SearchIndex>, query: String) -> impl IntoView {
    if query.trim().is_empty() {
        return view! { <p class="muted" role="status">"Start with a word or phrase."</p> }
            .into_any();
    }
    let hits = index.search(&query);
    let count = hits.len();
    let results = hits.into_iter().map(|hit| {
        let title = highlight_parts(&hit.document.title, &query);
        let excerpt = highlight_parts(&hit.excerpt, &query);
        let path = format!("/posts/{}/", hit.document.slug);
        view! {
            <article><h2 class="post-title"><A href=path><Highlighted parts=title /></A></h2><p><Highlighted parts=excerpt /></p></article>
        }
    }).collect_view();
    view! {
        <p class="muted" role="status">{if count == 0 { "No results. Try another word.".to_owned() } else { count_label(count, "result") }}</p>
        <div class="search-results">{results}</div>
    }.into_any()
}

#[component]
fn Highlighted(parts: Vec<(String, bool)>) -> impl IntoView {
    parts
        .into_iter()
        .map(|(text, matched)| {
            if matched {
                view! { <mark>{text}</mark> }.into_any()
            } else {
                text.into_any()
            }
        })
        .collect_view()
}

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <PageHeading title="Page not found" detail="404" />
        <p>"This page does not exist."</p>
        <A href="/" attr:class="archive-link">"Back to writing →"</A>
    }
}

fn count_label(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}
