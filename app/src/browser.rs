use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
include!(concat!(env!("OUT_DIR"), "/keys.rs"));

#[link(wasm_import_module = "dom")]
unsafe extern "C" {
    fn retain(value: u32) -> u32;
    fn release(value: u32);
    fn string(pointer: *const u8, length: usize) -> u32;
    fn object() -> u32;
    fn make_number(value: f64) -> u32;
    fn array(pointer: *const Arg, length: usize) -> u32;
    fn get(value: u32, key: Key) -> u32;
    fn try_get(value: u32, key: Key) -> i32;
    fn set(value: u32, key: Key, data: *const u8, kind: usize);
    fn call(value: u32, key: Key, args: *const Arg, count: usize) -> u32;
    fn call0(value: u32, key: Key) -> u32;
    fn call1(value: u32, key: Key, data: *const u8, kind: usize) -> u32;
    fn call2(
        value: u32,
        key: Key,
        data: *const u8,
        kind: usize,
        data2: *const u8,
        kind2: usize,
    ) -> u32;
    fn try_call(value: u32, key: Key, args: *const Arg, count: usize) -> i32;
    fn construct(key: Key, args: *const Arg, count: usize) -> i32;
    fn truthy(value: u32) -> bool;
    fn equal(a: u32, b: u32) -> bool;
    fn equal_text(value: u32, pointer: *const u8, length: usize) -> bool;
    fn numeric(value: u32) -> f64;
    fn instance(value: u32, key: Key) -> bool;
    fn string_length(value: u32) -> usize;
    fn string_copy(pointer: *mut u8);
    fn bytes_length(value: u32) -> usize;
    fn bytes_copy(value: u32, pointer: *mut u8);
    fn listen(value: u32, pointer: *const u8, length: usize, kind: u32);
    fn promise(value: u32, kind: u32, token: u32);
    fn timeout(milliseconds: i32, kind: u32, token: u32);
    fn frame(kind: u32, token: u32);
}

#[repr(C)]
pub struct Arg<'a> {
    data: *const u8,
    kind: usize,
    lifetime: PhantomData<&'a Js>,
}
impl<'a> Arg<'a> {
    pub fn string(value: &'a str) -> Self {
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
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Js(u32);

fn result(value: i32) -> Result<Js, Js> {
    if value < 0 {
        Err(Js((-value) as u32))
    } else {
        Ok(Js(value as u32))
    }
}

impl Js {
    pub fn retain(self) -> Self {
        Self(unsafe { retain(self.0) })
    }
    pub fn release(self) {
        if self.0 > 2 {
            unsafe { release(self.0) };
        }
    }
    pub fn arg(&self) -> Arg<'_> {
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
    pub fn is_null(&self) -> bool {
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
    pub fn array(values: &[Arg]) -> Self {
        Self(unsafe { array(values.as_ptr(), values.len()) })
    }
    #[inline(never)]
    pub fn try_get(&self, name: Key) -> Result<Self, Self> {
        result(unsafe { try_get(self.0, name) })
    }
    #[inline]
    pub fn get(&self, name: Key) -> Self {
        Self(unsafe { get(self.0, name) })
    }
    #[inline]
    pub fn set(&self, name: Key, value: Arg) {
        unsafe { set(self.0, name, value.data, value.kind) };
    }
    #[inline(never)]
    pub fn try_call(&self, name: Key, args: &[Arg]) -> Result<Self, Self> {
        result(unsafe { try_call(self.0, name, args.as_ptr(), args.len()) })
    }
    #[inline(always)]
    pub fn call(&self, name: Key, args: &[Arg]) -> Self {
        Self(unsafe {
            match args {
                [] => call0(self.0, name),
                [a] => call1(self.0, name, a.data, a.kind),
                [a, b] => call2(self.0, name, a.data, a.kind, b.data, b.kind),
                _ => call(self.0, name, args.as_ptr(), args.len()),
            }
        })
    }
    pub fn construct(name: Key, args: &[Arg]) -> Self {
        result(unsafe { construct(name, args.as_ptr(), args.len()) }).unwrap_or_else(|_| panic!())
    }
    pub fn same(&self, other: &Self) -> bool {
        unsafe { equal(self.0, other.0) }
    }
    pub fn equal_text(&self, text: &str) -> bool {
        unsafe { equal_text(self.0, text.as_ptr(), text.len()) }
    }
    pub fn truthy(&self) -> bool {
        unsafe { truthy(self.0) }
    }
    pub fn numeric(&self) -> f64 {
        unsafe { numeric(self.0) }
    }
    pub fn instance(&self, name: Key) -> bool {
        unsafe { instance(self.0, name) }
    }
    #[inline(never)]
    pub fn text(&self) -> String {
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
    pub fn bytes(&self) -> Vec<u8> {
        let length = unsafe { bytes_length(self.0) };
        let mut bytes = Vec::with_capacity(length);
        unsafe {
            bytes_copy(self.0, bytes.as_mut_ptr());
            bytes.set_len(length);
        }
        bytes
    }
    #[inline(never)]
    pub fn attr(&self, name: &'static str) -> String {
        self.call(Key::GetAttribute, &[Arg::literal(name)]).text()
    }
    #[inline(never)]
    pub fn set_attr(&self, name: &'static str, value: &str) {
        self.call(Key::SetAttribute, &[Arg::literal(name), Arg::string(value)]);
    }
    pub fn remove_attr(&self, name: &'static str) {
        self.call(Key::RemoveAttribute, &[Arg::literal(name)]);
    }
    pub fn has_attr(&self, name: &'static str) -> bool {
        self.call(Key::HasAttribute, &[Arg::literal(name)]).truthy()
    }
    pub fn query(&self, selector: &'static str) -> Self {
        self.call(Key::QuerySelector, &[Arg::literal(selector)])
    }
    pub fn closest(&self, selector: &'static str) -> Self {
        self.call(Key::Closest, &[Arg::literal(selector)])
    }
    pub fn duplicate(&self) -> Self {
        self.call(Key::CloneNode, &[Arg::boolean(true)])
    }
    pub fn set_text(&self, text: &str) {
        self.set(Key::TextContent, Arg::string(text));
    }
    pub fn subscribe(&self, kind: u32, token: u32) {
        unsafe { promise(self.0, kind, token) };
    }
    pub fn listen(&self, name: &str, kind: u32) {
        unsafe { listen(self.0, name.as_ptr(), name.len(), kind) };
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
pub fn number_text(value: f64) -> String {
    window().call(Key::String, &[Arg::number(value)]).text()
}
pub fn focus(element: &Js) {
    let options = Js::object();
    options.set(Key::PreventScroll, Arg::boolean(true));
    let _ = element.try_call(Key::Focus, &[options.arg()]);
}
pub fn mark(name: &str) {
    let _ = window()
        .get(Key::Performance)
        .try_call(Key::Mark, &[Arg::string(name)]);
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
    for i in 0..buttons.get(Key::Length).numeric() as u32 {
        let button = buttons.call(Key::Item, &[Arg::number(i as f64)]);
        button.set_attr(
            "aria-pressed",
            if button
                .call(Key::GetAttribute, &[Arg::literal("data-theme-choice")])
                .same(theme)
            {
                "true"
            } else {
                "false"
            },
        );
    }
}
