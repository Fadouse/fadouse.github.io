use alloc::{collections::BinaryHeap, string::String, vec::Vec};
use core::ops::Range;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "build", derive(serde::Serialize, serde::Deserialize))]
pub struct SearchText {
    pub text: String,
    pub normalized: String,
    // Only transformed or multi-character graphemes need a boundary record.
    pub spans: Vec<[usize; 4]>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "build", derive(serde::Serialize, serde::Deserialize))]
pub struct SearchEntry {
    pub slug: String,
    pub title: SearchText,
    pub tags: String,
    pub description: String,
    pub body: SearchText,
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

impl SearchText {
    fn source_offset(&self, offset: usize, end: bool) -> usize {
        let index = self.spans.partition_point(|span| span[0] < offset);
        if index == 0 {
            return offset;
        }
        let [_, to, source_from, source_to] = self.spans[index - 1];
        if offset < to {
            if end { source_to } else { source_from }
        } else {
            source_to + (offset - to)
        }
    }

    fn is_grapheme_boundary(&self, offset: usize) -> bool {
        let index = self.spans.partition_point(|span| span[2] < offset);
        index == 0 || offset >= self.spans[index - 1][3]
    }

    fn excerpt(&self, terms: &[&str]) -> Range<usize> {
        let first = terms
            .iter()
            .filter_map(|term| self.normalized.find(term))
            .min()
            .unwrap_or(0);
        let first = self.source_offset(first, false);
        let start = self.text[..first]
            .char_indices()
            .rev()
            .filter(|(offset, _)| self.is_grapheme_boundary(*offset))
            .nth(39)
            .map_or(0, |(offset, _)| offset);
        let end = self.text[start..]
            .char_indices()
            .map(|(offset, _)| start + offset)
            .filter(|offset| self.is_grapheme_boundary(*offset))
            .nth(180)
            .unwrap_or(self.text.len());
        start..end
    }
}

pub struct SearchHit<'a> {
    pub entry: &'a SearchEntry,
    pub excerpt: Range<usize>,
}

pub fn search<'a>(entries: &'a [SearchEntry], query: &str) -> Vec<SearchHit<'a>> {
    let terms: Vec<&str> = query.split_whitespace().collect();
    if terms.is_empty() {
        return Vec::new();
    }
    // Ranking and highlighting share one compact O(n log n) heap sort in WASM.
    let ranked: BinaryHeap<_> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let fields = [
                &entry.title.normalized,
                &entry.tags,
                &entry.description,
                &entry.body.normalized,
            ];
            let mut score = 0;
            for term in &terms {
                let weight = fields
                    .iter()
                    .zip([8, 4, 2, 1])
                    .filter(|(field, _)| field.contains(term))
                    .map(|(_, weight)| weight)
                    .sum::<usize>();
                if weight == 0 {
                    return None;
                }
                score += weight;
            }
            Some((usize::MAX - score, index))
        })
        .collect();
    ranked
        .into_sorted_vec()
        .into_iter()
        .map(|(_, index)| SearchHit {
            entry: &entries[index],
            excerpt: entries[index].body.excerpt(&terms),
        })
        .collect()
}

pub fn highlight_parts<'a>(
    text: &'a SearchText,
    query: &str,
    range: Range<usize>,
) -> Vec<(&'a str, bool)> {
    let mut ranges = BinaryHeap::new();
    for term in query.split_whitespace() {
        for (start, _) in text.normalized.match_indices(term) {
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
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges.into_sorted_vec() {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    let mut parts = Vec::new();
    let mut cursor = range.start;
    for (start, end) in merged {
        if start > cursor {
            parts.push((&text.text[cursor..start], false));
        }
        parts.push((&text.text[start..end], true));
        cursor = end;
    }
    if cursor < range.end {
        parts.push((&text.text[cursor..range.end], false));
    }
    parts
}

#[cfg(all(test, feature = "build"))]
mod tests {
    use super::*;

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
