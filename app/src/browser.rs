use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
include!(concat!(env!("OUT_DIR"), "/keys.rs"));

#[link(wasm_import_module = "d")]
unsafe extern "C" {
    #[link_name = "a"]
    fn retain(value: u32) -> u32;
    #[link_name = "c"]
    fn string(pointer: *const u8, length: usize) -> u32;
    #[link_name = "d"]
    fn object() -> u32;
    #[link_name = "e"]
    fn make_number(value: f64) -> u32;
    #[link_name = "f"]
    fn array(pointer: *const Arg, length: usize) -> u32;
    #[link_name = "g"]
    fn get(value: u32, key: Key) -> u32;
    #[link_name = "h"]
    fn get_number(value: u32, key: Key) -> f64;
    #[link_name = "i"]
    fn get_boolean(value: u32, key: Key) -> bool;
    #[link_name = "j"]
    fn try_get(value: u32, key: Key) -> i32;
    #[link_name = "k"]
    fn set(value: u32, key: Key, data: *const u8, kind: usize);
    #[link_name = "l"]
    fn call(value: u32, key: Key, args: *const Arg, count: usize) -> u32;
    #[link_name = "m"]
    fn call0(value: u32, key: Key) -> u32;
    #[link_name = "n"]
    fn call1(value: u32, key: Key, data: *const u8, kind: usize) -> u32;
    #[link_name = "o"]
    fn call2(
        value: u32,
        key: Key,
        data: *const u8,
        kind: usize,
        data2: *const u8,
        kind2: usize,
    ) -> u32;
    #[link_name = "p"]
    fn try_call(value: u32, key: Key, args: *const Arg, count: usize) -> i32;
    #[link_name = "q"]
    fn construct(key: Key, args: *const Arg, count: usize) -> i32;
    #[link_name = "r"]
    fn truthy(value: u32) -> bool;
    #[link_name = "s"]
    fn equal(a: u32, b: u32) -> bool;
    #[link_name = "t"]
    fn equal_text(value: u32, pointer: *const u8, length: usize) -> bool;
    #[link_name = "u"]
    fn numeric(value: u32) -> f64;
    #[link_name = "v"]
    fn instance(value: u32, key: Key) -> bool;
    #[link_name = "w"]
    fn string_length(value: u32) -> usize;
    #[link_name = "x"]
    fn string_copy(pointer: *mut u8);
    #[link_name = "y"]
    fn bytes_length(value: u32) -> usize;
    #[link_name = "z"]
    fn bytes_copy(value: u32, pointer: *mut u8);
    #[link_name = "A"]
    fn listen(value: u32, pointer: *const u8, length: usize);
    #[link_name = "B"]
    fn promise(value: u32, kind: u32, token: u32);
    #[link_name = "C"]
    fn timeout(milliseconds: i32, kind: u32, token: u32);
    #[link_name = "D"]
    fn frame(kind: u32, token: u32);
    #[link_name = "E"]
    fn try_call0(value: u32, key: Key) -> i32;
    #[link_name = "F"]
    fn try_call1(value: u32, key: Key, data: *const u8, kind: usize) -> i32;
    #[link_name = "G"]
    fn try_call2(
        value: u32,
        key: Key,
        data: *const u8,
        kind: usize,
        data2: *const u8,
        kind2: usize,
    ) -> i32;
    #[link_name = "H"]
    fn construct0(key: Key) -> i32;
    #[link_name = "I"]
    fn construct1(key: Key, data: *const u8, kind: usize) -> i32;
    #[link_name = "J"]
    fn construct2(key: Key, data: *const u8, kind: usize, data2: *const u8, kind2: usize) -> i32;
    #[link_name = "K"]
    fn array2(data: *const u8, kind: usize, data2: *const u8, kind2: usize) -> u32;
    #[link_name = "L"]
    fn array3(
        data: *const u8,
        kind: usize,
        data2: *const u8,
        kind2: usize,
        data3: *const u8,
        kind3: usize,
    ) -> u32;
    #[link_name = "M"]
    fn call3(
        value: u32,
        key: Key,
        data: *const u8,
        kind: usize,
        data2: *const u8,
        kind2: usize,
        data3: *const u8,
        kind3: usize,
    ) -> u32;
    #[link_name = "N"]
    fn get_index(value: u32, index: u32) -> u32;
    #[link_name = "O"]
    fn call1_boolean(value: u32, key: Key, data: *const u8, kind: usize) -> bool;
    #[link_name = "P"]
    fn replace_retained(old: u32, value: u32) -> u32;
    #[link_name = "Q"]
    fn call1_void(value: u32, key: Key, data: *const u8, kind: usize);
    #[link_name = "R"]
    fn get2(value: u32, key: Key, next: Key) -> u32;
}

#[repr(C)]
pub struct Arg<'a> {
    data: *const u8,
    kind: usize,
    lifetime: PhantomData<&'a Js>,
}
impl<'a> Arg<'a> {
    pub fn string(value: &'a str) -> Self {
        Self::bytes(value.as_bytes())
    }
    pub fn bytes(value: &'a [u8]) -> Self {
        Self {
            data: value.as_ptr(),
            kind: (value.len() + 1) * 2,
            lifetime: PhantomData,
        }
    }
    pub fn literal(value: &'static str) -> Self {
        Self {
            data: value.as_ptr(),
            kind: (value.len() + 1) * 2 + 1,
            lifetime: PhantomData,
        }
    }
    pub fn number(value: f64) -> Self {
        Self {
            data: unsafe { make_number(value) } as *const u8,
            kind: 0,
            lifetime: PhantomData,
        }
    }
    pub fn integer(value: u32) -> Self {
        Self {
            data: value as *const u8,
            kind: usize::MAX - 1,
            lifetime: PhantomData,
        }
    }
    pub fn boolean(value: bool) -> Self {
        Self {
            data: usize::from(value) as *const u8,
            kind: usize::MAX,
            lifetime: PhantomData,
        }
    }
    pub fn null() -> Self {
        Self {
            data: core::ptr::null(),
            kind: 0,
            lifetime: PhantomData,
        }
    }
}

// Browser handles are scoped to an exported callback. Values stored in WASM
// state are explicitly retained until their operation/cache lifetime ends.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Js(u32);

fn result(value: i32) -> Result<Js, Js> {
    if value < 0 {
        Err(Js((-value) as u32))
    } else {
        Ok(Js(value as u32))
    }
}

#[inline(never)]
fn constructed(value: i32) -> Js {
    assert!(value >= 0);
    Js(value as u32)
}

impl Js {
    pub fn replace(&mut self, value: Self) {
        *self = self.replacing(value);
    }
    pub fn replacing(self, value: Self) -> Self {
        Self(unsafe { replace_retained(self.0, value.0) })
    }
    pub fn retain(self) -> Self {
        Self(unsafe { retain(self.0) })
    }
    pub fn arg(self) -> Arg<'static> {
        Arg {
            data: self.0 as *const u8,
            kind: 0,
            lifetime: PhantomData,
        }
    }
    pub fn owned(value: u32) -> Self {
        Self(value)
    }
    pub fn null() -> Self {
        Self(0)
    }
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }
    pub fn from_bytes(value: &[u8]) -> Self {
        Self(unsafe { string(value.as_ptr(), value.len()) })
    }
    pub fn object() -> Self {
        Self(unsafe { object() })
    }
    #[inline(always)]
    pub fn array(values: &[Arg]) -> Self {
        Self(unsafe {
            match values {
                [a, b] => array2(a.data, a.kind, b.data, b.kind),
                [a, b, c] => array3(a.data, a.kind, b.data, b.kind, c.data, c.kind),
                _ => array(values.as_ptr(), values.len()),
            }
        })
    }
    #[inline(never)]
    pub fn try_get(self, name: Key) -> Result<Self, Self> {
        result(unsafe { try_get(self.0, name) })
    }
    #[inline]
    pub fn get(self, name: Key) -> Self {
        Self(unsafe { get(self.0, name) })
    }
    pub fn get2(self, name: Key, next: Key) -> Self {
        Self(unsafe { get2(self.0, name, next) })
    }
    pub fn call_void(self, name: Key, arg: Arg<'_>) {
        unsafe { call1_void(self.0, name, arg.data, arg.kind) };
    }
    pub fn number(self, name: Key) -> f64 {
        unsafe { get_number(self.0, name) }
    }
    pub fn boolean(self, name: Key) -> bool {
        unsafe { get_boolean(self.0, name) }
    }
    #[inline]
    pub fn set(self, name: Key, value: Arg) {
        unsafe { set(self.0, name, value.data, value.kind) };
    }
    #[inline(always)]
    pub fn try_call(self, name: Key, args: &[Arg]) -> Result<Self, Self> {
        result(unsafe {
            match args {
                [] => try_call0(self.0, name),
                [a] => try_call1(self.0, name, a.data, a.kind),
                [a, b] => try_call2(self.0, name, a.data, a.kind, b.data, b.kind),
                _ => try_call(self.0, name, args.as_ptr(), args.len()),
            }
        })
    }
    #[inline(always)]
    pub fn call(self, name: Key, args: &[Arg]) -> Self {
        Self(unsafe {
            match args {
                [] => call0(self.0, name),
                [a] => call1(self.0, name, a.data, a.kind),
                [a, b] => call2(self.0, name, a.data, a.kind, b.data, b.kind),
                [a, b, c] => call3(self.0, name, a.data, a.kind, b.data, b.kind, c.data, c.kind),
                _ => call(self.0, name, args.as_ptr(), args.len()),
            }
        })
    }
    #[inline(always)]
    pub fn construct(name: Key, args: &[Arg]) -> Self {
        constructed(unsafe {
            match args {
                [] => construct0(name),
                [a] => construct1(name, a.data, a.kind),
                [a, b] => construct2(name, a.data, a.kind, b.data, b.kind),
                _ => construct(name, args.as_ptr(), args.len()),
            }
        })
    }
    pub fn item(self, index: u32) -> Self {
        Self(unsafe { get_index(self.0, index) })
    }
    pub fn call_boolean(self, name: Key, arg: Arg<'_>) -> bool {
        unsafe { call1_boolean(self.0, name, arg.data, arg.kind) }
    }
    pub fn same(self, other: Self) -> bool {
        unsafe { equal(self.0, other.0) }
    }
    pub fn equal_text(self, text: &'static str) -> bool {
        unsafe { equal_text(self.0, text.as_ptr(), text.len()) }
    }
    pub fn truthy(self) -> bool {
        unsafe { truthy(self.0) }
    }
    pub fn numeric(self) -> f64 {
        unsafe { numeric(self.0) }
    }
    pub fn instance(self, name: Key) -> bool {
        unsafe { instance(self.0, name) }
    }
    #[inline(never)]
    pub fn text(self) -> String {
        if self.is_null() {
            return String::new();
        }
        let length = unsafe { string_length(self.0) };
        let mut bytes = Vec::with_capacity(length);
        // TextEncoder provides valid UTF-8; the host fills exactly length bytes.
        unsafe {
            string_copy(bytes.as_mut_ptr());
            bytes.set_len(length);
            String::from_utf8_unchecked(bytes)
        }
    }
    pub fn bytes(self) -> Vec<u8> {
        let length = unsafe { bytes_length(self.0) };
        let mut bytes = Vec::with_capacity(length);
        unsafe {
            bytes_copy(self.0, bytes.as_mut_ptr());
            bytes.set_len(length);
        }
        bytes
    }
    #[inline(never)]
    pub fn set_attr(self, name: &'static str, value: &'static str) {
        self.call(
            Key::SetAttribute,
            &[Arg::literal(name), Arg::literal(value)],
        );
    }
    pub fn remove_attr(self, name: &'static str) {
        self.call(Key::RemoveAttribute, &[Arg::literal(name)]);
    }
    pub fn has_attr(self, name: &'static str) -> bool {
        self.call_boolean(Key::HasAttribute, Arg::literal(name))
    }
    pub fn query(self, selector: &'static str) -> Self {
        self.call(Key::QuerySelector, &[Arg::literal(selector)])
    }
    pub fn closest(self, selector: &'static str) -> Self {
        self.call(Key::Closest, &[Arg::literal(selector)])
    }
    pub fn duplicate(self) -> Self {
        self.call(Key::CloneNode, &[Arg::boolean(true)])
    }
    pub fn set_text(self, text: &str) {
        self.set(Key::TextContent, Arg::string(text));
    }
    pub fn subscribe(self, kind: u32, token: u32) {
        unsafe { promise(self.0, kind, token) };
    }
    // Each static descriptor is one callback kind followed by a NUL-terminated
    // UTF-8 event name. The host only decodes and binds the supplied descriptors.
    pub fn listen(self, events: &'static [u8]) {
        unsafe { listen(self.0, events.as_ptr(), events.len()) };
    }
}

pub fn delay(milliseconds: i32, kind: u32, token: u32) {
    unsafe { timeout(milliseconds, kind, token) };
}
pub fn next_frame(kind: u32, token: u32) {
    unsafe { frame(kind, token) };
}
pub fn window() -> Js {
    Js(1)
}
pub fn document() -> Js {
    Js(2)
}
pub fn query(selector: &'static str) -> Js {
    document().query(selector)
}
pub fn required(selector: &'static str) -> Js {
    let value = query(selector);
    assert!(!value.is_null());
    value
}
pub fn location() -> Js {
    window().get(Key::Location)
}
pub fn url() -> Js {
    Js::construct(Key::Url, &[location().get(Key::Href).arg()])
}
pub fn template(selector: &'static str) -> Js {
    required(selector).get(Key::Content).duplicate()
}
pub fn focus(element: &Js) {
    let options = Js::object();
    options.set(Key::PreventScroll, Arg::boolean(true));
    let _ = element.try_call(Key::Focus, &[options.arg()]);
}
pub fn mark(name: &'static str) {
    let _ = window()
        .get(Key::Performance)
        .try_call(Key::Mark, &[Arg::literal(name)]);
}
pub fn saved_theme() -> Js {
    window()
        .try_get(Key::LocalStorage)
        .and_then(|storage| storage.try_call(Key::GetItem, &[Arg::literal("theme")]))
        .ok()
        .filter(|value| value.equal_text("light") || value.equal_text("dark"))
        .unwrap_or_else(|| Js::from_text("system"))
}
pub fn set_theme(theme: &Js) {
    let root = document().get(Key::DocumentElement);
    if theme.equal_text("system") {
        root.remove_attr("data-theme");
    } else {
        root.call(
            Key::SetAttribute,
            &[Arg::literal("data-theme"), theme.arg()],
        );
    }
    let _ = window()
        .try_get(Key::LocalStorage)
        .and_then(|storage| storage.try_call(Key::SetItem, &[Arg::literal("theme"), theme.arg()]));
    let buttons = document().call(
        Key::QuerySelectorAll,
        &[Arg::literal("[data-theme-choice]")],
    );
    for i in 0..buttons.number(Key::Length) as u32 {
        let button = buttons.item(i);
        button.set_attr(
            "aria-pressed",
            if button
                .call(Key::GetAttribute, &[Arg::literal("data-theme-choice")])
                .same(*theme)
            {
                "true"
            } else {
                "false"
            },
        );
    }
}
