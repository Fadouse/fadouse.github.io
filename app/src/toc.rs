use core::cell::Cell;

use crate::browser::{self, Arg, Js, Key, document, query, window};
use crate::motion;

#[derive(Clone, Copy)]
struct Scroll {
    started: f64,
    from: f64,
    to: f64,
}

pub struct Toc {
    headings: Cell<Js>,
    links: Cell<Js>,
    count: Cell<u32>,
    active: Cell<u32>,
    pending: Cell<bool>,
    geometry_dirty: Cell<bool>,
    scroll: Cell<Option<Scroll>>,
}

impl Default for Toc {
    fn default() -> Self {
        Self {
            headings: Cell::new(Js::null()),
            links: Cell::new(Js::null()),
            count: Cell::new(0),
            active: Cell::new(u32::MAX),
            pending: Cell::new(false),
            geometry_dirty: Cell::new(false),
            scroll: Cell::new(None),
        }
    }
}

impl Toc {
    pub fn scroll_to(&self, element: &Js) {
        let from = window().number(Key::ScrollY);
        let to = (from
            + element
                .call(Key::GetBoundingClientRect, &[])
                .number(Key::Top)
            - 32.0)
            .max(0.0)
            .min(
                document()
                    .get(Key::DocumentElement)
                    .number(Key::ScrollHeight)
                    - window().number(Key::InnerHeight),
            );
        self.scroll.set(Some(Scroll {
            started: now(),
            from,
            to,
        }));
        self.request();
    }

    pub fn cancel(&self) {
        self.scroll.set(None);
    }

    pub fn on_page(&self) {
        let links = query("#page-content").call(Key::QuerySelectorAll, &[Arg::literal(".toc a")]);
        // The renderer emits matching desktop and mobile lists, in that order.
        let count = links.number(Key::Length) as u32 / 2;
        // Only parsed Markdown headings have a generated heading anchor.
        let headings = query("#page-content").call(
            Key::QuerySelectorAll,
            &[Arg::literal(".prose [id]:has(> .heading-anchor)")],
        );
        self.links.set(self.links.get().replacing(links));
        self.headings.set(self.headings.get().replacing(headings));
        self.count.set(count);
        self.active.set(u32::MAX);
        self.request();
    }

    pub fn request(&self) {
        if self.count.get() != 0 && !self.pending.replace(true) {
            browser::next_frame(2, 0);
        }
    }

    pub fn refresh(&self) {
        self.geometry_dirty.set(true);
        self.request();
    }

    pub fn update(&self) {
        self.pending.set(false);
        let count = self.count.get();
        if count == 0 {
            return;
        }
        if let Some(scroll) = self.scroll.get() {
            let progress = ((now() - scroll.started) / 180.0).min(1.0);
            let remaining = 1.0 - progress;
            let position =
                scroll.to + (scroll.from - scroll.to) * remaining * remaining * remaining;
            window().call(Key::ScrollTo, &[Arg::integer(0), Arg::number(position)]);
            if progress < 1.0 {
                self.request();
            } else {
                self.cancel();
            }
        }
        let bottom = window().number(Key::ScrollY) + window().number(Key::InnerHeight)
            >= document()
                .get(Key::DocumentElement)
                .number(Key::ScrollHeight)
                - 1.0;
        let mut low = 0;
        let mut high = count;
        if bottom {
            low = count;
        } else {
            // Read geometry before changing attributes; large TOCs need only
            // logarithmically many heading reads per animation frame.
            while low < high {
                let middle = low + (high - low) / 2;
                let top = self
                    .headings
                    .get()
                    .item(middle)
                    .call(Key::GetBoundingClientRect, &[])
                    .number(Key::Top);
                if top <= 64.0 {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
        }
        let active = low.saturating_sub(1);
        let previous = self.active.replace(active);
        let refresh = self.geometry_dirty.replace(false);
        if previous == active && !refresh {
            return;
        }
        let link = self.links.get().item(active);
        // Offsets use the sidebar's content coordinates, including when it
        // scrolls. Read before writing, only when selection or layout changes.
        let top = link.number(Key::OffsetTop) + 4.0;
        let height = (link.number(Key::OffsetHeight) - 8.0).max(0.0);
        let sidebar = link.closest(".toc");
        let style = sidebar.get(Key::Style);
        if previous != u32::MAX {
            sidebar.set_attr("data-toc-motion", "");
        }
        for (property, value) in [("--toc-top", top), ("--toc-height", height)] {
            style.call(
                Key::SetProperty,
                &[Arg::literal(property), motion::pixels(value).arg()],
            );
        }
        if previous == active {
            return;
        }
        for offset in [0, count] {
            if previous != u32::MAX {
                self.links
                    .get()
                    .item(offset + previous)
                    .remove_attr("aria-current");
            }
            self.links
                .get()
                .item(offset + active)
                .set_attr("aria-current", "location");
        }
    }
}

fn now() -> f64 {
    window().get(Key::Performance).call(Key::Now, &[]).numeric()
}
