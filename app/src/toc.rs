// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use core::cell::Cell;

use crate::browser::{self, Arg, Js, Key, document, query, window};
use crate::motion;

#[derive(Clone, Copy)]
struct Scroll {
    started: f64,
    from: f64,
    to: f64,
    heading: f64,
}

pub struct Toc {
    headings: Cell<Js>,
    links: Cell<Js>,
    count: Cell<u32>,
    active: Cell<u32>,
    pending: Cell<bool>,
    geometry_dirty: Cell<bool>,
    scroll: Cell<Option<Scroll>>,
    reading: Cell<f64>,
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
            reading: Cell::new(motion::scalar(150)),
        }
    }
}

impl Toc {
    // Select an element and bring it into view: travelling when `smooth` and
    // this page tracks headings (the tracker drives the motion), otherwise at
    // once, with the finished scroll only holding the selection.
    pub fn scroll_to(&self, element: &Js, smooth: bool) {
        let smooth = smooth && self.count.get() != 0;
        if !smooth {
            element.call(Key::ScrollIntoView, &[]);
        }
        let from = window().number(Key::ScrollY);
        let heading = from
            + element
                .call(Key::GetBoundingClientRect, &[])
                .number(Key::Top);
        let mut started = motion::scalar(0);
        let mut to = from;
        if smooth {
            started = now();
            // The browser clamps an offset above the page; only the end
            // needs limiting, so the motion stops where scrolling does.
            to = (heading - motion::scalar(56)).min(
                document()
                    .get(Key::DocumentElement)
                    .number(Key::ScrollHeight)
                    - window().number(Key::InnerHeight),
            );
        }
        self.scroll.set(Some(Scroll {
            started,
            from,
            to,
            heading: heading + motion::scalar(1),
        }));
        self.request();
    }

    pub fn cancel(&self) {
        self.scroll.set(None);
    }

    pub fn on_page(&self) {
        let page = query(lit!("#page-content"));
        let links = page.call(Key::QuerySelectorAll, &[Arg::literal(lit!(".toc a"))]);
        // The renderer emits matching desktop and mobile lists, in that order.
        let count = links.uint(Key::Length) / 2;
        // Only parsed Markdown headings have a generated heading anchor.
        let headings = page.call(
            Key::QuerySelectorAll,
            &[Arg::literal(lit!(".prose [id]:has(>.heading-anchor)"))],
        );
        self.links.set(self.links.get().replacing(links));
        self.headings.set(self.headings.get().replacing(headings));
        self.count.set(count);
        self.active.set(u32::MAX);
        self.cancel();
        self.reading
            .set(window().number(Key::ScrollY) + motion::scalar(150));
        self.request();
    }

    pub fn request(&self) {
        if self.count.get() != 0 && !self.pending.replace(true) {
            browser::next_frame(2, 0);
        }
    }

    pub fn refresh(&self) {
        self.cancel();
        self.geometry_dirty.set(true);
        self.request();
    }

    pub fn update(&self) {
        self.pending.set(false);
        let count = self.count.get();
        if count == 0 {
            return;
        }
        let scrolling = self.scroll.get();
        if let Some(scroll) = scrolling {
            let progress = ((now() - scroll.started) / motion::scalar(180)).min(motion::scalar(1));
            let remaining = motion::scalar(1) - progress;
            let position =
                scroll.to + (scroll.from - scroll.to) * remaining * remaining * remaining;
            window().call(Key::ScrollTo, &[Arg::integer(0), Arg::number(position)]);
            if progress < motion::scalar(1) {
                self.request();
            }
        }
        let position = window().number(Key::ScrollY);
        let height = window().number(Key::InnerHeight);
        let document_height = document()
            .get(Key::DocumentElement)
            .number(Key::ScrollHeight);
        // mdBook's 150/300px directional reading band. Keeping its position in
        // document coordinates prevents a jump when the reader reverses.
        let down = (height * 0.25).min(motion::scalar(150));
        let reading = if let Some(scroll) = scrolling {
            // Keep an explicit destination selected until the reader scrolls,
            // even when the page end prevents aligning it with the top.
            scroll.heading
        } else if document_height > height
            && position + height >= document_height - motion::scalar(1)
        {
            document_height
        } else {
            self.reading
                .get()
                .max(position + down)
                .min(position + down * motion::scalar(2))
        };
        self.reading.set(reading);
        let threshold = reading - position;
        let mut low = 0;
        let mut high = count;
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
            if top <= threshold {
                low = middle + 1;
            } else {
                high = middle;
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
        let top = link.number(Key::OffsetTop) + motion::scalar(4);
        let height = (link.number(Key::OffsetHeight) - motion::scalar(8)).max(motion::scalar(0));
        let sidebar = link.closest(lit!(".toc"));
        let style = sidebar.get(Key::Style);
        sidebar.optional_attr(
            lit!("data-toc-motion"),
            lit!(""),
            previous != u32::MAX && !refresh,
        );
        for (property, value) in [(lit!("--toc-top"), top), (lit!("--toc-height"), height)] {
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
                    .remove_attr(lit!("aria-current"));
            }
            self.links
                .get()
                .item(offset + active)
                .set_attr(lit!("aria-current"), lit!("location"));
        }
    }
}

fn now() -> f64 {
    window().get(Key::Performance).call(Key::Now, &[]).numeric()
}
