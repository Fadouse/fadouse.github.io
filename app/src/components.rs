use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};
use shared::{Heading, PostSummary, tag_path};

use crate::{browser, catalog};

#[component]
pub fn Shell(children: Children) -> impl IntoView {
    let site = catalog().site.clone();
    let brand = site.title.clone();
    let location = use_location();
    browser::use_scroll_restoration();
    let theme = RwSignal::new(browser::saved_theme());
    view! {
        <a class="skip-link" href="#main-content">"Skip to content"</a>
        <div class="site-shell">
            <header class=move || if location.pathname.get() == "/" { "site-header home-header" } else { "site-header" }>
                <A href="/" exact=true attr:class="brand">{brand}</A>
                <nav class="navigation" aria-label="Main navigation">
                    <A href="/" exact=true>"Writing"</A>
                    <A href="/archive/">"Archive"</A>
                    <A href="/tags/">"Tags"</A>
                    <A href="/about/">"About"</A>
                    <A href="/search/" attr:class="search-link">"Search"</A>
                </nav>
            </header>
            <main class="page" id="main-content" tabindex="-1">
                <div id="page-content">{children()}</div>
            </main>
            <footer class="site-footer">
                <div class="footer-links"><span>{site.title}</span><a href="/feed.xml">"RSS ↗"</a></div>
                <div class="theme-picker" role="group" aria-label="Color theme">
                    {[ ("system", "System"), ("light", "Light"), ("dark", "Dark") ].into_iter().map(|(value, label)| view! {
                        <button type="button" aria-pressed=move || (theme.get() == value).to_string()
                            on:click=move |_| { browser::set_theme(value); theme.set(value.to_owned()); }>{label}</button>
                    }).collect_view()}
                </div>
            </footer>
        </div>
        <p class="sr-only" id="copy-status" aria-live="polite"></p>
    }
}

#[component]
pub fn ChangingContent<F, V>(view: F) -> impl IntoView
where
    F: Fn() -> V + Send + Sync + 'static,
    V: IntoView + 'static,
{
    let current = NodeRef::<leptos::html::Div>::new();
    view! {
        <div node_ref=current>{move || {
            let next = view();
            if let Some(element) = current.get_untracked() {
                browser::transition_content(&element);
            }
            next
        }}</div>
    }
}

#[component]
pub fn PageHeading(
    #[prop(into)] title: String,
    #[prop(optional, into)] detail: String,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="section-heading">
            <h1>{title}</h1>
            {(!detail.is_empty()).then(|| view! { <p>{detail}</p> })}
            {children.map(|children| children())}
        </div>
    }
}

#[component]
pub fn Tags(tags: Vec<String>) -> impl IntoView {
    view! {
        <div class="post-tags">{tags.into_iter().map(|tag| view! { <A href=tag_path(&tag)>{tag}</A> }).collect_view()}</div>
    }
}

#[component]
pub fn PostList(posts: Vec<PostSummary>) -> impl IntoView {
    if posts.is_empty() {
        return view! { <p class="empty-state">"No posts yet."</p> }.into_any();
    }
    view! {
        <ul class="post-list">{posts.into_iter().map(|post| view! { <PostRow post /> }).collect_view()}</ul>
    }.into_any()
}

#[component]
fn PostRow(post: PostSummary) -> impl IntoView {
    let path = post.path();
    let date_attribute = post.date.clone();
    view! {
        <li class="post-row">
            <time class="post-date" datetime=date_attribute>{post.date}</time>
            <article>
                <h2 class="post-title"><A href=path>{post.title}</A></h2>
                <p class="post-description">{post.description}</p>
                <Tags tags=post.tags />
            </article>
        </li>
    }
}

#[component]
pub fn ContentsList(headings: Vec<Heading>) -> impl IntoView {
    view! {
        <ul>{headings.into_iter().map(|heading| view! {
            <li class={if heading.level > 2 { "nested-heading" } else { "" }}>
                <a href=format!("#{}", heading.id)>{heading.text}</a>
            </li>
        }).collect_view()}</ul>
    }
}

#[component]
pub fn LoadError() -> impl IntoView {
    view! {
        <div class="error-state" role="alert">
            <h2>"Unable to load this page."</h2>
            <p>"Check your connection and try again."</p>
            <button type="button" on:click=|_| { let _ = browser::window().location().reload(); }>"Retry ↗"</button>
        </div>
    }
}

#[component]
pub fn Loading() -> impl IntoView {
    view! { <p class="muted" role="status">"Loading…"</p> }
}
