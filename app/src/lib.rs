#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;

mod browser;
mod motion;
mod search;
mod toc;

use browser::{Arg, Js, Key, document, location, query, required, window};
use core::cell::{Cell, UnsafeCell};

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: lol_alloc::AssumeSingleThreaded<lol_alloc::FreeListAllocator> =
    unsafe { lol_alloc::AssumeSingleThreaded::new(lol_alloc::FreeListAllocator::new()) };
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

const PAGE_RESPONSE: u32 = 0;
const PAGE_TEXT: u32 = 1;
const INDEX_RESPONSE: u32 = 2;
const INDEX_BYTES: u32 = 3;
const COPY: u32 = 4;
const LEAVING: u32 = 5;

struct App {
    path: Cell<Js>,
    navigation: Cell<u32>,
    next: Cell<u32>,
    pages: Js,
    positions: Js,
    requests: Js,
    copies: Js,
    leaving: Js,
    search: search::Search,
    toc: toc::Toc,
}
struct BrowserApp(UnsafeCell<Option<App>>);
// One main-thread instance is initialized before any callbacks; subsequent
// mutations use Cell/RefCell and never replace the App.
unsafe impl Sync for BrowserApp {}
static APP: BrowserApp = BrowserApp(UnsafeCell::new(None));
fn app() -> &'static App {
    unsafe { (*APP.0.get()).as_ref().unwrap() }
}

fn page_read(doc: &Js) -> Js {
    let content = doc.call(Key::GetElementById, &[Arg::literal("page-content")]);
    if content.is_null() {
        return Js::null();
    }
    let nodes = doc.call(Key::QuerySelectorAll, &[Arg::literal("[data-page-meta]")]);
    let metadata = doc.call(Key::CreateDocumentFragment, &[]);
    for i in 0..nodes.get(Key::Length).numeric() as u32 {
        metadata.call(
            Key::AppendChild,
            &[nodes
                .call(Key::Item, &[Arg::number(i as f64)])
                .duplicate()
                .arg()],
        );
    }
    Js::array(&[content.duplicate().arg(), metadata.arg()])
}

#[unsafe(no_mangle)]
pub extern "C" fn start() {
    browser::mark("wasm-start");
    let map = || Js::construct(Key::Map, &[]).retain();
    unsafe {
        *APP.0.get() = Some(App {
            path: Cell::new(location().get(Key::Pathname).retain()),
            navigation: Cell::new(0),
            next: Cell::new(0),
            pages: map(),
            positions: map(),
            requests: map(),
            copies: map(),
            leaving: map(),
            search: search::Search::default(),
            toc: toc::Toc::default(),
        })
    };
    browser::set_theme(&browser::saved_theme());
    document()
        .get(Key::DocumentElement)
        .get(Key::ClassList)
        .call(Key::Add, &[Arg::literal("js")]);
    app().pages.call(
        Key::Set,
        &[app().path.get().arg(), page_read(&document()).arg()],
    );
    window()
        .get(Key::History)
        .set(Key::ScrollRestoration, Arg::literal("manual"));
    for (kind, name) in ["click", "keydown"].iter().enumerate() {
        document().listen(name, kind as u32);
    }
    for (kind, name) in ["popstate", "scroll"].iter().enumerate() {
        window().listen(name, kind as u32 + 2);
    }
    window().listen("resize", 8);
    for name in ["wheel", "pointerdown"] {
        window().listen(name, 9);
    }
    for (kind, name) in ["input", "submit", "compositionstart", "compositionend"]
        .iter()
        .enumerate()
    {
        document().listen(name, kind as u32 + 4);
    }
    app().search.on_page();
    app().toc.on_page();
    browser::mark("app-mounted");
}

#[unsafe(no_mangle)]
pub extern "C" fn dispatch(kind: u32, value: u32) {
    let event = Js::owned(value);
    match kind {
        0 => app().click(&event),
        1 => app().keydown(&event),
        2 => app().navigate(browser::url(), false, false),
        3 => {
            app().record_scroll();
            app().toc.request();
        }
        8 => app().toc.request(),
        9 => app().toc.cancel(),
        _ => app().search.event(kind, &event),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn resolved(kind: u32, token: u32, value: u32) {
    let value = Js::owned(value);
    match kind {
        PAGE_RESPONSE | INDEX_RESPONSE => {
            if !value.get(Key::Ok).truthy() && value.get(Key::Status).numeric() != 404.0 {
                rejected(kind, token);
                return;
            }
            let (method, next) = if kind == PAGE_RESPONSE {
                (Key::Text, PAGE_TEXT)
            } else {
                (Key::ArrayBuffer, INDEX_BYTES)
            };
            match value.try_call(method, &[]) {
                Ok(promise) => promise.subscribe(next, token),
                Err(_) => rejected(next, token),
            }
        }
        PAGE_TEXT => {
            let parser = Js::construct(Key::DomParser, &[]);
            let page = parser
                .try_call(
                    Key::ParseFromString,
                    &[value.arg(), Arg::literal("text/html")],
                )
                .map(|doc| page_read(&doc))
                .unwrap_or(Js::null());
            app().page_ready(token, page);
        }
        INDEX_BYTES => app()
            .search
            .loaded(shared::search::Index::new(value.bytes())),
        COPY => app().copied(token, true),
        LEAVING => timer(1, token),
        _ => {}
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn rejected(kind: u32, token: u32) {
    match kind {
        PAGE_RESPONSE | PAGE_TEXT => app().page_ready(token, Js::null()),
        INDEX_RESPONSE | INDEX_BYTES => app().search.loaded(None),
        COPY => app().copied(token, false),
        LEAVING => timer(1, token),
        _ => {}
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn timer(kind: u32, token: u32) {
    if kind == 2 {
        app().toc.update();
        return;
    }
    let list = if kind == 0 {
        &app().copies
    } else {
        &app().leaving
    };
    let element = list.call(Key::Get, &[Arg::number(token as f64)]);
    if !element.is_null() {
        list.call(Key::Delete, &[Arg::number(token as f64)]);
        if kind == 0 {
            element.set_text("Copy");
        } else {
            element.call(Key::Remove, &[]);
        }
    }
}
fn target(event: &Js) -> Js {
    let target = event.get(Key::Target);
    if target.instance(Key::Element) {
        target
    } else {
        Js::null()
    }
}

impl App {
    fn token(&self) -> u32 {
        let token = self.next.get() + 1;
        self.next.set(token);
        token
    }
    fn set_path(&self, path: Js) {
        self.path.replace(path.retain()).release();
    }
    fn record_scroll(&self) {
        self.positions.call(
            Key::Set,
            &[self.path.get().arg(), window().get(Key::ScrollY).arg()],
        );
    }
    fn click(&self, event: &Js) {
        if event.get(Key::Button).numeric() != 0.0
            || [Key::CtrlKey, Key::MetaKey, Key::AltKey, Key::ShiftKey]
                .iter()
                .any(|key| event.get(*key).truthy())
        {
            return;
        }
        let target = target(event);
        if target.is_null() {
            return;
        }
        let button = target.closest("[data-theme-choice]");
        if !button.is_null() {
            browser::set_theme(
                &button.call(Key::GetAttribute, &[Arg::literal("data-theme-choice")]),
            );
            return;
        }
        let button = target.closest("button[data-copy]");
        if !button.is_null() {
            self.copy_code(button);
            return;
        }
        if !target.closest("[data-retry]").is_null() {
            if !query("#search-input").is_null() {
                self.search.on_page();
                focus_search_input();
            } else {
                self.navigate(browser::url(), false, false);
            }
            return;
        }
        let anchor = target.closest("a[href]");
        if anchor.is_null() || anchor.has_attr("download") {
            return;
        }
        let target = anchor.call(Key::GetAttribute, &[Arg::literal("target")]);
        if !target.is_null() && !target.equal_text("") && !target.equal_text("_self") {
            return;
        }
        let url = Js::construct(
            Key::Url,
            &[
                anchor
                    .call(Key::GetAttribute, &[Arg::literal("href")])
                    .arg(),
                location().get(Key::Href).arg(),
            ],
        );
        let path = url.get(Key::Pathname);
        if !url.get(Key::Origin).same(&location().get(Key::Origin))
            || !path.call(Key::EndsWith, &[Arg::literal("/")]).truthy()
        {
            return;
        }
        if path.same(&location().get(Key::Pathname)) && !url.get(Key::Hash).equal_text("") {
            if !anchor.closest(".toc").is_null() && scroll_to_hash(&url, !motion::reduced()) {
                event.call(Key::PreventDefault, &[]);
                if !url.get(Key::Href).same(&location().get(Key::Href)) {
                    push_url(&url);
                }
            }
            return;
        }
        event.call(Key::PreventDefault, &[]);
        if !url.get(Key::Href).same(&location().get(Key::Href)) {
            self.navigate(url, true, false);
        }
    }
    fn keydown(&self, event: &Js) {
        self.toc.cancel();
        let key = event.get(Key::Key);
        if (event.get(Key::MetaKey).truthy() || event.get(Key::CtrlKey).truthy())
            && !event.get(Key::AltKey).truthy()
            && !event.get(Key::ShiftKey).truthy()
            && (key.equal_text("k") || key.equal_text("K"))
        {
            event.call(Key::PreventDefault, &[]);
            if !query("#search-input").is_null() {
                focus_search_input();
                return;
            }
            self.navigate(
                Js::construct(
                    Key::Url,
                    &[Arg::literal("/search/"), location().get(Key::Href).arg()],
                ),
                true,
                true,
            );
        }
    }
    fn navigate(&self, url: Js, push: bool, focus_search: bool) {
        self.toc.cancel();
        self.record_scroll();
        let contents = query("#page-content .mobile-toc");
        if !contents.is_null() {
            self.pages
                .call(Key::Get, &[self.path.get().arg()])
                .call(Key::At, &[Arg::number(0.0)])
                .query(".mobile-toc")
                .set(Key::Open, contents.get(Key::Open).arg());
        }
        let path = url.get(Key::Pathname);
        let token = self.token();
        self.navigation.set(token);
        let cached = self.pages.call(Key::Get, &[path.arg()]);
        let position = if push {
            0.0
        } else {
            let value = self.positions.call(Key::Get, &[path.arg()]);
            if value.is_null() {
                0.0
            } else {
                value.numeric()
            }
        };
        if push && !url.get(Key::Href).same(&location().get(Key::Href)) {
            push_url(&url);
        }
        if self.path.get().same(&path) && !cached.is_null() {
            required("#main-content").remove_attr("aria-busy");
            self.search.on_page();
            if focus_search {
                focus_search_input();
            } else if !push {
                restore_position(&url, position);
            }
            return;
        }
        if !cached.is_null() {
            self.commit(&url, &cached, position, focus_search);
            return;
        }
        required("#main-content").set_attr("aria-busy", "true");
        required("#navigation-status").set_text("Loading page…");
        self.requests.call(
            Key::Set,
            &[
                Arg::number(token as f64),
                Js::array(&[url.arg(), Arg::number(position), Arg::boolean(focus_search)]).arg(),
            ],
        );
        match window().try_call(Key::Fetch, &[path.arg()]) {
            Ok(promise) => promise.subscribe(PAGE_RESPONSE, token),
            Err(_) => self.page_ready(token, Js::null()),
        }
    }
    fn page_ready(&self, token: u32, page: Js) {
        let request = self.requests.call(Key::Get, &[Arg::number(token as f64)]);
        if request.is_null() {
            return;
        }
        self.requests
            .call(Key::Delete, &[Arg::number(token as f64)]);
        let url = request.call(Key::At, &[Arg::number(0.0)]);
        let path = url.get(Key::Pathname);
        let current = self.navigation.get() == token;
        if !page.is_null() {
            self.pages.call(Key::Set, &[path.arg(), page.arg()]);
            if current {
                self.commit(
                    &url,
                    &page,
                    request.call(Key::At, &[Arg::number(1.0)]).numeric(),
                    request.call(Key::At, &[Arg::number(2.0)]).truthy(),
                );
            }
        } else if current {
            self.set_path(path);
            update_header(&path);
            motion::replace_html(
                &required("#page-content"),
                "<div class=\"error-state\" role=\"alert\"><h1>Unable to load this page.</h1><p>Check your connection and try again.</p><button type=\"button\" data-retry>Retry ↗</button></div>",
                true,
            );
            required("#main-content").remove_attr("aria-busy");
            required("#navigation-status").set_text("Unable to load this page.");
            restore_position(&url, 0.0);
            self.toc.on_page();
        }
    }
    fn commit(&self, url: &Js, page: &Js, position: f64, focus_search: bool) {
        let path = url.get(Key::Pathname);
        self.set_path(path);
        update_header(&path);
        motion::replace(
            &required("#page-content"),
            &page.call(Key::At, &[Arg::number(0.0)]).duplicate(),
            position == 0.0 && url.get(Key::Hash).equal_text(""),
        );
        required("#main-content").remove_attr("aria-busy");
        let nodes = document().call(Key::QuerySelectorAll, &[Arg::literal("[data-page-meta]")]);
        for i in 0..nodes.get(Key::Length).numeric() as u32 {
            nodes
                .call(Key::Item, &[Arg::number(i as f64)])
                .call(Key::Remove, &[]);
        }
        document().get(Key::Head).call(
            Key::AppendChild,
            &[page.call(Key::At, &[Arg::number(1.0)]).duplicate().arg()],
        );
        required("#navigation-status").set(Key::TextContent, document().get(Key::Title).arg());
        restore_position(url, position);
        self.search.on_page();
        self.toc.on_page();
        if focus_search {
            focus_search_input();
        }
        browser::mark("page-rendered");
    }
    fn copy_code(&self, button: Js) {
        let code = button
            .closest(".code-block")
            .query("code")
            .get(Key::TextContent);
        let token = self.token();
        self.copies
            .call(Key::Set, &[Arg::number(token as f64), button.arg()]);
        match window()
            .get(Key::Navigator)
            .get(Key::Clipboard)
            .try_call(Key::WriteText, &[code.arg()])
        {
            Ok(promise) => promise.subscribe(COPY, token),
            Err(_) => self.copied(token, false),
        }
    }
    fn copied(&self, token: u32, copied: bool) {
        let button = self.copies.call(Key::Get, &[Arg::number(token as f64)]);
        if !button.is_null() {
            let message = if copied { "Copied" } else { "Copy failed" };
            button.set_text(message);
            required("#copy-status").set_text(message);
            browser::delay(1800, 0, token);
        }
    }
    fn remove_after(&self, element: Js, promise: &Js) {
        let token = self.token();
        self.leaving
            .call(Key::Set, &[Arg::number(token as f64), element.arg()]);
        promise.subscribe(LEAVING, token);
    }
}

fn update_header(path: &Js) {
    let home = path.equal_text("/");
    required(".site-header").set(
        Key::ClassName,
        Arg::string(if home {
            "site-header home-header"
        } else {
            "site-header"
        }),
    );
    let heading = required("#brand-heading");
    heading.set_attr("role", if home { "heading" } else { "none" });
    if home {
        heading.set_attr("aria-level", "1");
        required(".brand").set_attr("aria-current", "page");
    } else {
        heading.remove_attr("aria-level");
        required(".brand").remove_attr("aria-current");
    }
    let links = document().call(Key::QuerySelectorAll, &[Arg::literal("[data-nav]")]);
    for i in 0..links.get(Key::Length).numeric() as u32 {
        let link = links.call(Key::Item, &[Arg::number(i as f64)]);
        let href = link.call(Key::GetAttribute, &[Arg::literal("href")]);
        if !href.equal_text("/") && path.call(Key::StartsWith, &[href.arg()]).truthy() {
            link.set_attr("aria-current", "page");
        } else {
            link.remove_attr("aria-current");
        }
    }
}
fn push_url(url: &Js) {
    window().get(Key::History).call(
        Key::PushState,
        &[Arg::null(), Arg::literal(""), url.get(Key::Href).arg()],
    );
}
fn scroll_to_hash(url: &Js, smooth: bool) -> bool {
    let mut hash = url.get(Key::Hash);
    let has_hash = !hash.equal_text("");
    while hash.call(Key::StartsWith, &[Arg::literal("#")]).truthy() {
        hash = hash.call(Key::Slice, &[Arg::number(1.0)]);
    }
    if has_hash && let Ok(id) = window().try_call(Key::DecodeURIComponent, &[hash.arg()]) {
        let element = document().call(Key::GetElementById, &[id.arg()]);
        if !element.is_null() {
            element.set_attr("tabindex", "-1");
            browser::focus(&element);
            if smooth {
                app().toc.scroll_to(&element);
            } else {
                element.call(Key::ScrollIntoView, &[]);
            }
            return true;
        }
    }
    false
}
fn restore_position(url: &Js, position: f64) {
    if scroll_to_hash(url, false) {
        return;
    }
    window().call(Key::ScrollTo, &[Arg::number(0.0), Arg::number(position)]);
    browser::focus(&required("#main-content"));
}
fn focus_search_input() {
    let input = query("#search-input");
    if !input.is_null() {
        browser::focus(&input);
        input.call(Key::Select, &[]);
    }
}
