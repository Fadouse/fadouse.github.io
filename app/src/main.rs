mod browser;
mod components;
mod pages;

use std::sync::Arc;

use leptos::{mount::mount_to, prelude::*};
use leptos_meta::{Link, Meta, Title, provide_meta_context};
use leptos_router::{
    components::{Route, Router, Routes},
    hooks::use_location,
    path,
};
use shared::{Bootstrap, Catalog, page_metadata};
use wasm_bindgen::JsCast;

use components::{LoadError, Shell};
use pages::{
    AboutPage, ArchivePage, HomePage, NotFoundPage, PostPage, SearchPage, TagPage, TagsPage, route,
};

fn main() {
    browser::apply_saved_theme();
    browser::mark("wasm-start");
    wasm_bindgen_futures::spawn_local(async {
        let document = browser::document();
        let bootstrap = document
            .get_element_by_id("site-bootstrap")
            .expect("Site bootstrap data");
        let bootstrap: Bootstrap =
            serde_json::from_str(&bootstrap.text_content().unwrap_or_default())
                .expect("Generated bootstrap JSON");
        let catalog = browser::fetch_json::<Catalog>(&bootstrap.catalog_url).await;
        let root = document
            .get_element_by_id("app")
            .expect("Application mount point");
        root.set_inner_html("");
        // Leptos owns route metadata after startup; remove the static crawler copy.
        let metadata = document
            .query_selector_all("[data-page-meta]")
            .expect("Metadata selector");
        for index in 0..metadata.length() {
            metadata
                .item(index)
                .expect("Metadata element")
                .unchecked_into::<web_sys::Element>()
                .remove();
        }
        match catalog {
            Ok(catalog) => {
                mount_to(root.unchecked_into(), move || view! { <App catalog /> }).forget();
                browser::mark("app-mounted");
            }
            Err(_) => {
                mount_to(
                    root.unchecked_into(),
                    || view! { <div class="boot-message"><LoadError /></div> },
                )
                .forget();
            }
        }
    });
}

#[component]
fn App(catalog: Catalog) -> impl IntoView {
    provide_context(Arc::new(catalog));
    provide_meta_context();
    browser::prepare_history();
    view! {
        <Router>
            <Metadata />
            <Shell>
                <Routes fallback=route(NotFoundPage)>
                    <Route path=path!("") view=route(HomePage) />
                    <Route path=path!("archive") view=route(ArchivePage) />
                    <Route path=path!("tags") view=route(TagsPage) />
                    <Route path=path!("tags/:tag") view=TagPage />
                    <Route path=path!("posts/:slug") view=PostPage />
                    <Route path=path!("search") view=route(SearchPage) />
                    <Route path=path!("about") view=route(AboutPage) />
                </Routes>
            </Shell>
        </Router>
    }
}

pub fn catalog() -> Arc<Catalog> {
    expect_context::<Arc<Catalog>>()
}

#[component]
fn Metadata() -> impl IntoView {
    let catalog = catalog();
    let location = use_location();
    let metadata = Memo::new(move |_| page_metadata(&catalog, &location.pathname.get()));
    view! {
        <Title text=move || metadata.get().title />
        <Meta name="description" content=move || metadata.get().description />
        {move || view! { <Link rel="canonical" href=metadata.get().canonical /> }}
        <Meta property="og:title" content=move || metadata.get().title />
        <Meta property="og:description" content=move || metadata.get().description />
        <Meta property="og:url" content=move || metadata.get().canonical />
        <Meta property="og:type" content=move || if metadata.get().article { "article" } else { "website" } />
        <Meta name="twitter:card" content="summary" />
        <Meta name="twitter:title" content=move || metadata.get().title />
        <Meta name="twitter:description" content=move || metadata.get().description />
        <Meta name="robots" content=move || if metadata.get().noindex { "noindex,follow" } else { "index,follow" } />
    }
}
