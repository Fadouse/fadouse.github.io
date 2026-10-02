// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use alloc::{string::String, vec::Vec};
use core::ops::Range;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "build", derive(serde::Serialize, serde::Deserialize))]
pub struct SearchText<S = String, B = Vec<[usize; 4]>> {
    pub text: S,
    pub normalized: S,
    // Only transformed or multi-character graphemes need a boundary record.
    pub spans: B,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "build", derive(serde::Serialize, serde::Deserialize))]
pub struct SearchEntry<S = String, B = Vec<[usize; 4]>> {
    pub slug: S,
    pub title: SearchText<S, B>,
    pub tags: S,
    pub description: S,
    pub body: SearchText<S, B>,
}

// Length-prefixed UTF-8 and little-endian u32 boundaries avoid JSON parsing
// and per-field browser/WASM calls when loading the generated index.
#[cfg(feature = "build")]
pub fn encode_index(entries: &[SearchEntry]) -> Vec<u8> {
    fn number(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend_from_slice(&u32::try_from(value).expect("WASM index size").to_le_bytes());
    }
    fn string(bytes: &mut Vec<u8>, value: &str) {
        number(bytes, value.len());
        bytes.extend_from_slice(value.as_bytes());
    }
    fn text(bytes: &mut Vec<u8>, value: &SearchText) {
        string(bytes, &value.text);
        string(bytes, &value.normalized);
        number(bytes, value.spans.len());
        for span in &value.spans {
            for offset in span {
                number(bytes, *offset);
            }
        }
    }
    let mut bytes = Vec::new();
    number(&mut bytes, entries.len());
    for entry in entries {
        string(&mut bytes, &entry.slug);
        text(&mut bytes, &entry.title);
        string(&mut bytes, &entry.tags);
        string(&mut bytes, &entry.description);
        text(&mut bytes, &entry.body);
    }
    bytes
}

pub trait SpanList {
    fn len(&self) -> usize;
    fn span(&self, index: usize) -> [usize; 4];
    fn at(&self, index: usize, column: usize) -> usize {
        self.span(index)[column]
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[inline(never)]
    fn partition_point(&self, column: usize, offset: usize) -> usize {
        let mut left = 0;
        let mut right = self.len();
        while left < right {
            let mid = left + (right - left) / 2;
            if self.at(mid, column) < offset {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        left
    }
}
impl SpanList for Vec<[usize; 4]> {
    fn len(&self) -> usize {
        self.as_slice().len()
    }
    fn span(&self, index: usize) -> [usize; 4] {
        self[index]
    }
}
#[derive(Clone, Copy)]
pub struct BorrowedSpans<'a>(&'a [u8]);
impl SpanList for BorrowedSpans<'_> {
    fn len(&self) -> usize {
        self.0.len() / 16
    }
    fn span(&self, index: usize) -> [usize; 4] {
        let bytes = &self.0[index * 16..][..16];
        // The checked slice contains one complete record; downloaded string
        // lengths need not align it to four bytes.
        let span: [u32; 4] = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
        span.map(|offset| u32::from_le(offset) as usize)
    }
    fn at(&self, index: usize, column: usize) -> usize {
        assert!(index < self.len() && column < 4);
        // These bounds contain the entire unaligned u32 within one record.
        let pointer = unsafe { self.0.as_ptr().add(index * 16 + column * 4) };
        u32::from_le(unsafe { core::ptr::read_unaligned(pointer.cast()) }) as usize
    }
}
type Entry<'a> = SearchEntry<&'a str, BorrowedSpans<'a>>;
struct Reader<'a>(&'a [u8]);

// Boolean validation avoids constructing UTF-8 error reports that the index
// loader never uses. Reject overlong encodings, surrogates and values > U+10FFFF.
fn valid_utf8(bytes: &[u8]) -> bool {
    let mut remaining = 0;
    let mut minimum = 0x80;
    let mut maximum = 0xbf;
    for &byte in bytes {
        if remaining != 0 {
            if byte < minimum || byte > maximum {
                return false;
            }
            remaining -= 1;
            minimum = 0x80;
            maximum = 0xbf;
        } else if byte >= 0x80 {
            if !(0xc2..=0xf4).contains(&byte) {
                return false;
            }
            remaining = if byte < 0xe0 {
                1
            } else if byte < 0xf0 {
                2
            } else {
                3
            };
            minimum = match byte {
                0xe0 => 0xa0,
                0xf0 => 0x90,
                _ => 0x80,
            };
            maximum = match byte {
                0xed => 0x9f,
                0xf4 => 0x8f,
                _ => 0xbf,
            };
        }
    }
    remaining == 0
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(value)
    }
    fn number(&mut self) -> Option<usize> {
        let bytes = self.take(4)?;
        // The checked field may be unaligned after preceding UTF-8 strings.
        Some(u32::from_le(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) }) as usize)
    }
    fn string(&mut self) -> Option<&'a str> {
        let length = self.number()?;
        let bytes = self.take(length)?;
        if !valid_utf8(bytes) {
            return None;
        }
        // Every immutable string view is validated before it is constructed.
        Some(unsafe { core::str::from_utf8_unchecked(bytes) })
    }
    fn text(&mut self) -> Option<SearchText<&'a str, BorrowedSpans<'a>>> {
        let text = self.string()?;
        let normalized = self.string()?;
        let count = self.number()?;
        let spans = BorrowedSpans(self.take(count.checked_mul(16)?)?);
        Some(SearchText {
            text,
            normalized,
            spans,
        })
    }
    fn entry(&mut self) -> Option<Entry<'a>> {
        Some(SearchEntry {
            slug: self.string()?,
            title: self.text()?,
            tags: self.string()?,
            description: self.string()?,
            body: self.text()?,
        })
    }
}
// The index retains one immutable download. Strings and Unicode boundaries
// are borrowed from it instead of allocating each field in every article.
pub struct Index {
    entries: Vec<Entry<'static>>,
    _bytes: Vec<u8>,
}
impl Index {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        // The immutable Vec keeps the allocation at a fixed address. These
        // internal views are dropped with Index and only exposed with the
        // lifetime of &self by entries(), never with their stored lifetime.
        let mut reader =
            Reader(unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) });
        let count = reader.number()?;
        let mut entries = Vec::new();
        for _ in 0..count {
            entries.push(reader.entry()?);
        }
        if !reader.0.is_empty() {
            return None;
        }
        Some(Self {
            entries,
            _bytes: bytes,
        })
    }
    pub fn entries(&self) -> &[Entry<'_>] {
        &self.entries
    }
}

#[cfg(feature = "build")]
pub fn normalize(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text.nfkc()
        .flat_map(char::to_lowercase)
        .map(|character| if character == 'ς' { 'σ' } else { character })
        .collect()
}

#[cfg(feature = "build")]
impl SearchText {
    pub fn new(text: String) -> Self {
        use unicode_segmentation::UnicodeSegmentation;
        let mut normalized = String::new();
        let mut spans = Vec::new();
        for (start, grapheme) in text.grapheme_indices(true) {
            let folded = normalize(grapheme);
            let offset = normalized.len();
            normalized.push_str(&folded);
            if grapheme.chars().count() > 1
                || folded.chars().count() > 1
                || grapheme.len() != folded.len()
            {
                spans.push([offset, normalized.len(), start, start + grapheme.len()]);
            }
        }
        Self {
            text,
            normalized,
            spans,
        }
    }
}

#[cfg(feature = "build")]
impl From<&crate::SearchDocument> for SearchEntry {
    fn from(source: &crate::SearchDocument) -> Self {
        Self {
            slug: source.slug.clone(),
            title: SearchText::new(source.title.clone()),
            tags: normalize(&source.tags),
            description: normalize(&source.description),
            body: SearchText::new(source.text.clone()),
        }
    }
}

impl<S: AsRef<str>, B: SpanList> SearchText<S, B> {
    fn source_offset(&self, offset: usize, end: bool) -> usize {
        let index = self.spans.partition_point(0, offset);
        if index == 0 {
            return offset;
        }
        let to = self.spans.at(index - 1, 1);
        let column = 2 + usize::from(end | (offset >= to));
        self.spans.at(index - 1, column) + offset.saturating_sub(to)
    }

    fn is_grapheme_boundary(&self, offset: usize) -> bool {
        let index = self.spans.partition_point(2, offset);
        index == 0 || offset >= self.spans.at(index - 1, 3)
    }

    fn excerpt(&self, terms: &[&str]) -> Range<usize> {
        let mut first = usize::MAX;
        for term in terms {
            first = first.min(find_bytes(
                self.normalized.as_ref().as_bytes(),
                term.as_bytes(),
            ));
        }
        let first = if first == usize::MAX { 0 } else { first };
        let first = self.source_offset(first, false);
        let bytes = self.text.as_ref().as_bytes();
        let before = &bytes[..first];
        let mut start = before.len();
        let mut remaining = 40;
        while start > 0 && remaining > 0 {
            start -= 1;
            if before[start] & 0xc0 != 0x80 && self.is_grapheme_boundary(start) {
                remaining -= 1;
            }
        }
        let mut end = start;
        let mut length = 0;
        while end < bytes.len() {
            if bytes[end] & 0xc0 != 0x80 && self.is_grapheme_boundary(end) {
                if length == 180 {
                    break;
                }
                length += 1;
            }
            end += 1;
        }
        start..end
    }
}

pub struct SearchHit<'a, S = String, B = Vec<[usize; 4]>> {
    pub entry: &'a SearchEntry<S, B>,
    pub excerpt: Range<usize>,
}

// UTF-8 substring matching needs byte equality; matches of a valid UTF-8
// needle also start and end on character boundaries. Skip directly to its
// first byte instead of linking the general-purpose str pattern machinery.
pub fn find(text: &str, needle: &str) -> Option<usize> {
    let offset = find_bytes(text.as_bytes(), needle.as_bytes());
    (offset != usize::MAX).then_some(offset)
}
// A valid slice offset cannot equal usize::MAX. A scalar sentinel keeps the
// shared scan in one register instead of returning an Option through memory.
fn find_bytes(bytes: &[u8], needle: &[u8]) -> usize {
    let Some(&first) = needle.first() else {
        return usize::MAX;
    };
    bytes
        .windows(needle.len())
        .position(|window| window[0] == first && window == needle)
        .unwrap_or(usize::MAX)
}

// Unicode White_Space, matching str::split_whitespace exactly. Scan UTF-8
// boundaries directly so the browser build does not need generic str patterns.
pub fn terms(query: &str) -> Vec<&str> {
    let bytes = query.as_bytes();
    let mut terms = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let length = match &bytes[cursor..] {
            [9..=13 | 32, ..] => 1,
            [0xc2, 0x85 | 0xa0, ..] => 2,
            [0xe1, 0x9a, 0x80, ..]
            | [0xe2, 0x80, 0x80..=0x8a | 0xa8 | 0xa9 | 0xaf, ..]
            | [0xe2, 0x81, 0x9f, ..]
            | [0xe3, 0x80, 0x80, ..] => 3,
            _ => 0,
        };
        if length == 0 {
            cursor += 1;
            continue;
        }
        if start < cursor {
            // Only complete White_Space sequences split a valid UTF-8 query.
            terms.push(unsafe { core::str::from_utf8_unchecked(&bytes[start..cursor]) });
        }
        cursor += length;
        start = cursor;
    }
    if start < cursor {
        terms.push(unsafe { core::str::from_utf8_unchecked(&bytes[start..cursor]) });
    }
    terms
}

#[cfg(feature = "build")]
pub fn search<'a, S: AsRef<str>, B: SpanList>(
    entries: &'a [SearchEntry<S, B>],
    query: &str,
) -> Vec<SearchHit<'a, S, B>> {
    search_terms(entries, &terms(query)).collect()
}
pub fn search_terms<'a, S: AsRef<str>, B: SpanList>(
    entries: &'a [SearchEntry<S, B>],
    terms: &[&str],
) -> impl ExactSizeIterator<Item = SearchHit<'a, S, B>> {
    let mut ranked = Vec::new();
    if !terms.is_empty() {
        'entries: for (index, entry) in entries.iter().enumerate() {
            let mut score = 0;
            for term in terms {
                let weight = usize::from(find(entry.title.normalized.as_ref(), term).is_some()) * 8
                    + usize::from(find(entry.tags.as_ref(), term).is_some()) * 4
                    + usize::from(find(entry.description.as_ref(), term).is_some()) * 2
                    + usize::from(find(entry.body.normalized.as_ref(), term).is_some());
                if weight == 0 {
                    continue 'entries;
                }
                score += weight;
            }
            ranked.push((usize::MAX - score, index));
        }
    }
    sort_pairs(&mut ranked);
    ranked.into_iter().map(|(_, index)| SearchHit {
        entry: &entries[index],
        excerpt: entries[index].body.excerpt(terms),
    })
}

// Search scores and highlight ranges share this in-place O(n log n) sort.
fn sort_pairs(pairs: &mut [(usize, usize)]) {
    // The private caller guarantees root < end <= pairs.len(). Child indices
    // are checked against end before access, and each move follows that child.
    unsafe fn sift(pairs: &mut [(usize, usize)], mut root: usize, end: usize) {
        let value = unsafe { *pairs.get_unchecked(root) };
        loop {
            let mut child = root * 2 + 1;
            if child >= end {
                break;
            }
            if child + 1 < end
                && unsafe { pairs.get_unchecked(child) < pairs.get_unchecked(child + 1) }
            {
                child += 1;
            }
            let next = unsafe { *pairs.get_unchecked(child) };
            if value >= next {
                break;
            }
            unsafe {
                *pairs.get_unchecked_mut(root) = next;
            }
            root = child;
        }
        unsafe {
            *pairs.get_unchecked_mut(root) = value;
        }
    }
    for root in (0..pairs.len() / 2).rev() {
        unsafe {
            sift(pairs, root, pairs.len());
        }
    }
    for end in (1..pairs.len()).rev() {
        // This loop only runs for nonempty slices and 1 <= end < len.
        unsafe {
            core::ptr::swap(pairs.as_mut_ptr(), pairs.as_mut_ptr().add(end));
        }
        unsafe {
            sift(pairs, 0, end);
        }
    }
}

pub struct Highlight<'a> {
    bytes: &'a [u8],
    ranges: Vec<(usize, usize)>,
    index: usize,
    cursor: usize,
    end: usize,
}
impl<'a> Iterator for Highlight<'a> {
    type Item = (&'a [u8], bool);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(&(start, end)) = self.ranges.get(self.index) {
            if self.cursor < start {
                let previous = self.cursor;
                self.cursor = start;
                return Some((&self.bytes[previous..start], false));
            }
            self.index += 1;
            self.cursor = end;
            return Some((&self.bytes[start..end], true));
        }
        if self.cursor < self.end {
            let previous = self.cursor;
            self.cursor = self.end;
            return Some((&self.bytes[previous..self.end], false));
        }
        None
    }
}

pub fn highlight_bytes<'a, S: AsRef<str>, B: SpanList>(
    text: &'a SearchText<S, B>,
    terms: &[&str],
    range: Range<usize>,
) -> Highlight<'a> {
    let mut ranges = Vec::new();
    for term in terms {
        let mut cursor = 0;
        loop {
            let offset = find_bytes(
                &text.normalized.as_ref().as_bytes()[cursor..],
                term.as_bytes(),
            );
            if offset == usize::MAX {
                break;
            }
            let start = cursor + offset;
            cursor = start + term.len();
            let source_start = text.source_offset(start, false);
            if source_start >= range.end {
                break;
            }
            let end = text.source_offset(start + term.len(), true).min(range.end);
            let start = source_start.max(range.start);
            if start < end {
                ranges.push((start, end));
            }
        }
    }
    sort_pairs(&mut ranges);
    let mut merged = 0;
    for index in 0..ranges.len() {
        let (start, end) = ranges[index];
        if merged > 0 && start <= ranges[merged - 1].1 {
            ranges[merged - 1].1 = ranges[merged - 1].1.max(end);
        } else {
            ranges[merged] = (start, end);
            merged += 1;
        }
    }
    ranges.truncate(merged);
    Highlight {
        bytes: text.text.as_ref().as_bytes(),
        ranges,
        index: 0,
        cursor: range.start,
        end: range.end,
    }
}

#[cfg(feature = "build")]
pub fn highlight_parts<'a, S: AsRef<str>, B: SpanList>(
    text: &'a SearchText<S, B>,
    query: &str,
    range: Range<usize>,
) -> Vec<(&'a str, bool)> {
    highlight_bytes(text, &terms(query), range)
        .map(|(bytes, matched)| (core::str::from_utf8(bytes).unwrap(), matched))
        .collect()
}

#[cfg(all(test, feature = "build"))]
mod tests {
    use super::*;

    #[test]
    fn compact_sort_and_matching_preserve_standard_order_and_offsets() {
        let mut seed = 0x7813u32;
        for length in [0, 1, 2, 3, 8, 31, 256, 4096] {
            let mut pairs = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                pairs.push(((seed >> 20) as usize, (seed & 31) as usize));
            }
            let mut expected = pairs.clone();
            expected.sort_unstable();
            sort_pairs(&mut pairs);
            assert_eq!(pairs, expected);
            pairs.reverse();
            sort_pairs(&mut pairs);
            assert_eq!(pairs, expected);
        }
        for text in ["Hello 世界, café 👩‍💻", "aaaaabaaaaab", "", "ﬃ ﬃ cafe\u{301}"] {
            for start in (0..text.len()).filter(|offset| text.is_char_boundary(*offset)) {
                for end in (start + 1..=text.len()).filter(|offset| text.is_char_boundary(*offset))
                {
                    let needle = &text[start..end];
                    assert_eq!(find(text, needle), text.find(needle));
                }
            }
            for missing in ["missing", "longer than the source with no match"] {
                assert_eq!(find(text, missing), text.find(missing));
            }
        }
    }

    #[test]
    fn excerpts_preserve_context_and_complete_graphemes() {
        use unicode_segmentation::UnicodeSegmentation;

        for grapheme in ["a", "世界", "cafe\u{301} ", "👩‍💻 "] {
            for (before, after) in [(10, 220), (80, 220), (80, 5)] {
                let source = alloc::format!(
                    "{}needle{}",
                    grapheme.repeat(before),
                    grapheme.repeat(after)
                );
                let first = source.find("needle").unwrap();
                let boundaries: Vec<_> = source
                    .grapheme_indices(true)
                    .map(|(offset, _)| offset)
                    .collect();
                let hit = boundaries.partition_point(|offset| *offset < first);
                let start = hit.saturating_sub(40);
                let expected =
                    boundaries[start]..boundaries.get(start + 180).copied().unwrap_or(source.len());
                let text = SearchText::new(source);
                assert_eq!(
                    text.excerpt(&["needle"]),
                    expected,
                    "{grapheme} {before} {after}"
                );
            }
        }
    }

    #[test]
    fn compact_utf8_and_whitespace_match_standard_library() {
        for value in 0..=0x10ffff {
            let Some(character) = char::from_u32(value) else {
                continue;
            };
            let mut bytes = [0; 4];
            let encoded = character.encode_utf8(&mut bytes);
            assert!(valid_utf8(encoded.as_bytes()), "U+{value:X}");
            let query = alloc::format!("left{encoded}right");
            assert_eq!(
                terms(&query),
                query.split_whitespace().collect::<Vec<_>>(),
                "U+{value:X}"
            );
        }
        let mut seed = 0x7813u32;
        for _ in 0..100_000 {
            let mut bytes = [0; 8];
            for byte in &mut bytes {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (seed >> 24) as u8;
            }
            for length in 1..=bytes.len() {
                assert_eq!(
                    valid_utf8(&bytes[..length]),
                    core::str::from_utf8(&bytes[..length]).is_ok(),
                    "{bytes:?} length {length}"
                );
            }
        }
    }

    #[test]
    fn binary_index_preserves_search_and_rejects_corrupt_downloads() {
        let entries: Vec<_> = [
            ("greeting", "HELLO 世界", "cafe\u{301} ﬃ 👩‍💻 Hello 世界"),
            ("notes", "Notes", "世界 cafe\u{301} Hello"),
        ]
        .into_iter()
        .map(|(slug, title, body)| SearchEntry {
            slug: slug.into(),
            title: SearchText::new(title.into()),
            tags: normalize("Hello multilingual"),
            description: normalize("世界"),
            body: SearchText::new(body.into()),
        })
        .collect();
        let bytes = encode_index(&entries);
        let index = Index::new(bytes.clone()).unwrap();
        let borrowed = index.entries();
        for query in [
            "HELLO 世界",
            "café",
            "f",
            "👩",
            "missing",
            " \u{85}\u{3000}",
        ] {
            let query = normalize(query);
            let owned_hits = search(&entries, &query);
            let borrowed_hits = search(borrowed, &query);
            assert_eq!(owned_hits.len(), borrowed_hits.len());
            for (owned, borrowed) in owned_hits.iter().zip(&borrowed_hits) {
                assert_eq!(owned.entry.slug, borrowed.entry.slug);
                assert_eq!(owned.excerpt, borrowed.excerpt);
                assert_eq!(
                    highlight_parts(&owned.entry.body, &query, owned.excerpt.clone()),
                    highlight_parts(&borrowed.entry.body, &query, borrowed.excerpt.clone())
                );
            }
        }
        for length in 0..bytes.len() {
            assert!(Index::new(bytes[..length].to_vec()).is_none());
        }
        let mut invalid = bytes.clone();
        invalid[8] = 0xff;
        assert!(Index::new(invalid).is_none());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Index::new(trailing).is_none());
    }

    #[test]
    fn search_ranks_titles_and_matches_mixed_language() {
        let entries: Vec<_> = [
            ("Other notes", "Hello 世界 in a paragraph."),
            ("Hello 世界", "A multilingual greeting."),
        ]
        .into_iter()
        .map(|(title, body)| SearchEntry {
            slug: String::new(),
            title: SearchText::new(title.into()),
            tags: String::new(),
            description: String::new(),
            body: SearchText::new(body.into()),
        })
        .collect();
        let hits = search(&entries, &normalize("HELLO 世界"));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].entry.title.text, "Hello 世界");
        assert!(search(&entries, "missing").is_empty());
    }

    #[test]
    fn highlighting_preserves_unicode_and_combining_marks() {
        let text = SearchText::new("Hello 世界, cafe\u{301} ﬃ 👩‍💻".into());
        let parts = highlight_parts(&text, &normalize("世界 café f 👩"), 0..text.text.len());
        assert_eq!(
            parts.iter().map(|part| part.0).collect::<String>(),
            text.text
        );
        assert_eq!(
            parts
                .iter()
                .filter(|part| part.1)
                .map(|part| part.0)
                .collect::<Vec<_>>(),
            ["世界", "cafe\u{301}", "ﬃ", "👩‍💻"]
        );

        let surrounding = "👩‍💻e\u{301}".repeat(100);
        let long = SearchText::new(alloc::format!("{surrounding}needle{surrounding}"));
        let excerpt = long.excerpt(&["needle"]);
        assert_eq!(
            &long.text[excerpt.clone()],
            alloc::format!(
                "{}needle{}",
                "👩‍💻e\u{301}".repeat(20),
                "👩‍💻e\u{301}".repeat(67)
            )
        );
        assert_eq!(
            highlight_parts(&long, "needle", excerpt)
                .into_iter()
                .filter(|part| part.1)
                .collect::<Vec<_>>(),
            [("needle", true)]
        );
    }
}
