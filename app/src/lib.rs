// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

#![cfg_attr(target_arch = "wasm32", no_std)]
extern crate alloc;

#[macro_use]
mod browser;
mod math_copy;
mod motion;
mod search;
mod toc;

use browser::{Arg, Js, Key, document, location, query, required, window};
use core::cell::{Cell, UnsafeCell};
use core::mem::MaybeUninit;

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
    math_copy: math_copy::MathCopy,
}
struct BrowserApp(UnsafeCell<MaybeUninit<App>>);
// One main-thread instance is initialized before any callbacks; subsequent
// mutations use Cell/RefCell and never replace the App.
unsafe impl Sync for BrowserApp {}
static APP: BrowserApp = BrowserApp(UnsafeCell::new(MaybeUninit::uninit()));
fn app() -> &'static App {
    unsafe { (*APP.0.get()).assume_init_ref() }
}

fn page_read(doc: Js) -> Js {
    let content = doc.call(Key::GetElementById, &[Arg::literal(lit!("page-content"))]);
    if content.is_null() {
        return Js::null();
    }
    let nodes = doc.call(
        Key::QuerySelectorAll,
        &[Arg::literal(lit!("[data-page-meta]"))],
    );
    let metadata = doc.call(Key::CreateDocumentFragment, &[]);
    for i in 0..nodes.uint(Key::Length) {
        metadata.call_void(Key::Append, nodes.item(i).duplicate().arg());
    }
    Js::array(&[content.duplicate().arg(), metadata.arg()])
}

#[unsafe(no_mangle)]
pub extern "C" fn start() {
    browser::initialize_literals();
    browser::mark(lit!("wasm-start"));
    let map = || Js::construct(Key::Map, &[]).retain();
    unsafe {
        (*APP.0.get()).write(App {
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
            math_copy: math_copy::MathCopy::new(),
        })
    };
    browser::set_theme(&browser::saved_theme());
    document()
        .get2(Key::DocumentElement, Key::ClassList)
        .call(Key::Add, &[Arg::literal(lit!("js"))]);
    app().pages.call(
        Key::Set,
        &[app().path.get().arg(), page_read(document()).arg()],
    );
    window()
        .get(Key::History)
        .set(Key::ScrollRestoration, Arg::literal(lit!("manual")));
    document().listen(b"\x00click\0\x01keydown\0\x04input\0\x05submit\0\x06compositionstart\0\x07compositionend\0\x0cfocusin\0");
    window().listen(b"\x02popstate\0\x83scroll\0\x08resize\0\x09wheel\0\x09pointerdown\0");
    let viewport = window().get(Key::VisualViewport);
    if !viewport.is_null() {
        viewport.listen(b"\x0escroll\0\x0eresize\0");
    }
    app().search.on_page();
    app().toc.on_page();
    browser::mark(lit!("app-mounted"));
}

#[unsafe(no_mangle)]
pub extern "C" fn dispatch(kind: u32, value: u32) {
    let event = Js::owned(value);
    match kind {
        0 => app().click(&event),
        1 => app().keydown(&event),
        2 => app().navigate(browser::url(), false, false),
        3 => {
            app().math_copy.scroll(&event);
            app().toc.request();
        }
        8 => {
            app().math_copy.close();
            app().toc.refresh();
        }
        9 => {
            app().math_copy.pointer_down(&event);
            app().toc.cancel();
        }
        12 => app().math_copy.focus(&event),
        14 => app().math_copy.close(),
        _ => app().search.event(kind, &event),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn resolved(kind: u32, token: u32, value: u32) {
    let value = Js::owned(value);
    match kind {
        PAGE_RESPONSE | INDEX_RESPONSE => {
            if !value.boolean(Key::Ok) && value.number(Key::Status) != 404.0 {
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
                    &[value.arg(), Arg::literal(lit!("text/html"))],
                )
                .map(page_read)
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
    let element = list.call(Key::Get, &[Arg::integer(token)]);
    if !element.is_null() {
        list.call(Key::Delete, &[Arg::integer(token)]);
        if kind == 0 {
            if app().math_copy.is_button(element) {
                app().math_copy.reset_copy();
            } else {
                element.set_text(lit!("Copy"));
            }
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
    #[inline(never)]
    fn token(&self) -> u32 {
        let token = self.next.get() + 1;
        self.next.set(token);
        token
    }
    fn set_path(&self, path: Js) {
        self.path.set(self.path.get().replacing(path));
    }
    fn record_scroll(&self) {
        self.positions.call(
            Key::Set,
            &[self.path.get().arg(), window().get(Key::ScrollY).arg()],
        );
    }
    fn click(&self, event: &Js) {
        if event.uint(Key::Button) != 0
            || event.boolean(Key::CtrlKey)
            || event.boolean(Key::MetaKey)
            || event.boolean(Key::AltKey)
            || event.boolean(Key::ShiftKey)
        {
            return;
        }
        let target = target(event);
        if target.is_null() {
            return;
        }
        let button = target.closest(lit!("[data-theme-choice]"));
        if !button.is_null() {
            browser::set_theme(&button.call(
                Key::GetAttribute,
                &[Arg::literal(lit!("data-theme-choice"))],
            ));
            return;
        }
        let button = target.closest(lit!("button[data-copy]"));
        if !button.is_null() {
            self.copy(button);
            return;
        }
        if self.math_copy.activate(event, target) {
            return;
        }
        if !target.closest(lit!("[data-retry]")).is_null() {
            if !query(lit!("#search-input")).is_null() {
                self.search.on_page();
                focus_search_input();
            } else {
                self.navigate(browser::url(), false, false);
            }
            return;
        }
        let anchor = target.closest(lit!("a[href]"));
        if anchor.is_null() || anchor.has_attr(lit!("download")) {
            return;
        }
        let target = anchor.call(Key::GetAttribute, &[Arg::literal(lit!("target"))]);
        if !target.is_null() && !target.equal_text(lit!("")) && !target.equal_text(lit!("_self")) {
            return;
        }
        let url = Js::construct(
            Key::Url,
            &[
                anchor
                    .call(Key::GetAttribute, &[Arg::literal(lit!("href"))])
                    .arg(),
                location().get(Key::Href).arg(),
            ],
        );
        let path = url.get(Key::Pathname);
        if !url.get(Key::Origin).same(location().get(Key::Origin))
            || !path.call_boolean(Key::EndsWith, Arg::literal(lit!("/")))
        {
            return;
        }
        if path.same(location().get(Key::Pathname)) && !url.get(Key::Hash).equal_text(lit!("")) {
            if !anchor.closest(lit!(".toc")).is_null() && scroll_to_hash(url, !motion::reduced()) {
                event.call(Key::PreventDefault, &[]);
                if !url.get(Key::Href).same(location().get(Key::Href)) {
                    push_url(&url);
                }
            }
            return;
        }
        event.call(Key::PreventDefault, &[]);
        if !url.get(Key::Href).same(location().get(Key::Href)) {
            self.navigate(url, true, false);
        }
    }
    fn keydown(&self, event: &Js) {
        self.toc.cancel();
        if self.math_copy.keydown(event) {
            return;
        }
        let key = event.get(Key::Key);
        if (event.boolean(Key::MetaKey) || event.boolean(Key::CtrlKey))
            && !event.boolean(Key::AltKey)
            && !event.boolean(Key::ShiftKey)
            && (key.equal_text(lit!("k")) || key.equal_text(lit!("K")))
        {
            event.call(Key::PreventDefault, &[]);
            if !query(lit!("#search-input")).is_null() {
                focus_search_input();
                return;
            }
            self.navigate(
                Js::construct(
                    Key::Url,
                    &[
                        Arg::literal(lit!("/search/")),
                        location().get(Key::Href).arg(),
                    ],
                ),
                true,
                true,
            );
        }
    }
    fn navigate(&self, url: Js, push: bool, focus_search: bool) {
        self.math_copy.detach();
        self.toc.cancel();
        self.record_scroll();
        let contents = query(lit!("main .mobile-toc"));
        if !contents.is_null() {
            self.pages
                .call(Key::Get, &[self.path.get().arg()])
                .item(0)
                .query(lit!(".mobile-toc"))
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
        if push && !url.get(Key::Href).same(location().get(Key::Href)) {
            push_url(&url);
        }
        if self.path.get().same(path) && !cached.is_null() {
            required(lit!("#main-content")).remove_attr(lit!("aria-busy"));
            self.search.on_page();
            if focus_search {
                focus_search_input();
            } else if !push {
                restore_position(url, position);
            }
            return;
        }
        if !cached.is_null() {
            self.commit(url, cached, position, focus_search);
            return;
        }
        required(lit!("#main-content")).set_attr(lit!("aria-busy"), lit!("true"));
        required(lit!("#navigation-status")).set_text(lit!("Loading page…"));
        self.requests.call(
            Key::Set,
            &[
                Arg::integer(token),
                Js::array(&[url.arg(), Arg::number(position), Arg::boolean(focus_search)]).arg(),
            ],
        );
        match window().try_call(Key::Fetch, &[path.arg()]) {
            Ok(promise) => promise.subscribe(PAGE_RESPONSE, token),
            Err(_) => self.page_ready(token, Js::null()),
        }
    }
    fn page_ready(&self, token: u32, page: Js) {
        let request = self.requests.call(Key::Get, &[Arg::integer(token)]);
        if request.is_null() {
            return;
        }
        self.requests.call(Key::Delete, &[Arg::integer(token)]);
        let url = request.item(0);
        let path = url.get(Key::Pathname);
        let current = self.navigation.get() == token;
        // A reader may keep scrolling while the next page is downloading.
        if current {
            self.record_scroll();
        }
        if !page.is_null() {
            self.pages.call(Key::Set, &[path.arg(), page.arg()]);
            if current {
                self.commit(
                    url,
                    page,
                    request.item(1).numeric(),
                    request.item(2).truthy(),
                );
            }
        } else if current {
            self.math_copy.detach();
            self.set_path(path);
            let current = required(lit!("#page-content"));
            let incoming = current.call(Key::CloneNode, &[]);
            incoming.call_void(Key::Append, browser::template(lit!("#page-error")).arg());
            motion::replace(current, incoming, true, path);
            required(lit!("#main-content")).remove_attr(lit!("aria-busy"));
            required(lit!("#navigation-status")).set_text(lit!("Unable to load this page."));
            restore_position(url, 0.0);
            self.toc.on_page();
        }
    }
    fn commit(&self, url: Js, page: Js, position: f64, focus_search: bool) {
        self.math_copy.detach();
        let path = url.get(Key::Pathname);
        self.set_path(path);
        motion::replace(
            required(lit!("#page-content")),
            page.item(0).duplicate(),
            position == 0.0 && url.get(Key::Hash).equal_text(lit!("")),
            path,
        );
        required(lit!("#main-content")).remove_attr(lit!("aria-busy"));
        let nodes = document().call(
            Key::QuerySelectorAll,
            &[Arg::literal(lit!("[data-page-meta]"))],
        );
        for i in 0..nodes.uint(Key::Length) {
            nodes.item(i).call(Key::Remove, &[]);
        }
        document()
            .get(Key::Head)
            .call_void(Key::Append, page.item(1).duplicate().arg());
        required(lit!("#navigation-status"))
            .set(Key::TextContent, document().get(Key::Title).arg());
        restore_position(url, position);
        self.search.on_page();
        self.toc.on_page();
        if focus_search {
            focus_search_input();
        }
        browser::mark(lit!("page-rendered"));
    }
    fn copy(&self, button: Js) {
        let token = self.token();
        let text = if self.math_copy.is_button(button) {
            let text = self.math_copy.begin_copy(token);
            if text.is_null() {
                return;
            }
            text
        } else {
            button
                .closest(lit!(".code-block"))
                .query(lit!("code"))
                .get(Key::TextContent)
        };
        required(lit!("#copy-status")).set_text(lit!(""));
        self.copies
            .call(Key::Set, &[Arg::integer(token), button.arg()]);
        match window()
            .get2(Key::Navigator, Key::Clipboard)
            .try_call(Key::WriteText, &[text.arg()])
        {
            Ok(promise) => promise.subscribe(COPY, token),
            Err(_) => self.copied(token, false),
        }
    }
    fn copied(&self, token: u32, copied: bool) {
        let button = self.copies.call(Key::Get, &[Arg::integer(token)]);
        if !button.is_null() {
            // Removed map entries fence off superseded promises and timers.
            if self.math_copy.is_button(button) {
                math_copy::MathCopy::finished(button);
            }
            let message = if copied {
                lit!("Copied")
            } else {
                lit!("Copy failed")
            };
            button.set_text(message);
            required(lit!("#copy-status")).set_text(message);
            browser::delay(1800, 0, token);
        }
    }
    fn remove_after(&self, element: Js, promise: &Js) {
        let token = self.token();
        self.leaving
            .call(Key::Set, &[Arg::integer(token), element.arg()]);
        promise.subscribe(LEAVING, token);
    }
}

fn update_header(path: Js) {
    let home = path.equal_text(lit!("/"));
    required(lit!(".site-header")).set(
        Key::ClassName,
        Arg::literal(if home {
            lit!("site-header home-header")
        } else {
            lit!("site-header")
        }),
    );
    let heading = required(lit!("#brand-heading"));
    heading.set_attr(
        lit!("role"),
        if home { lit!("heading") } else { lit!("none") },
    );
    let brand = required(lit!(".brand"));
    heading.optional_attr(lit!("aria-level"), lit!("1"), home);
    brand.optional_attr(lit!("aria-current"), lit!("page"), home);
    let links = document().call(Key::QuerySelectorAll, &[Arg::literal(lit!("[data-nav]"))]);
    for i in 0..links.uint(Key::Length) {
        let link = links.item(i);
        let href = link.get(Key::Pathname);
        link.optional_attr(
            lit!("aria-current"),
            lit!("page"),
            href.same(path)
                || (!href.equal_text(lit!("/")) && path.call_boolean(Key::StartsWith, href.arg())),
        );
    }
}
fn push_url(url: &Js) {
    window().get(Key::History).call(
        Key::PushState,
        &[
            Arg::null(),
            Arg::literal(lit!("")),
            url.get(Key::Href).arg(),
        ],
    );
}
fn scroll_to_hash(url: Js, smooth: bool) -> bool {
    let mut hash = url.get(Key::Hash);
    let has_hash = !hash.equal_text(lit!(""));
    while hash.call_boolean(Key::StartsWith, Arg::literal(lit!("#"))) {
        hash = hash.call(Key::Slice, &[Arg::integer(1)]);
    }
    if has_hash && let Ok(id) = window().try_call(Key::DecodeURIComponent, &[hash.arg()]) {
        let element = document().call(Key::GetElementById, &[id.arg()]);
        if !element.is_null() {
            element.set_attr(lit!("tabindex"), lit!("-1"));
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
fn restore_position(url: Js, position: f64) {
    if scroll_to_hash(url, false) {
        return;
    }
    window().call(Key::ScrollTo, &[Arg::integer(0), Arg::number(position)]);
    browser::focus(&required(lit!("#main-content")));
}
fn focus_search_input() {
    let input = query(lit!("#search-input"));
    if !input.is_null() {
        browser::focus(&input);
        input.call(Key::Select, &[]);
    }
}
