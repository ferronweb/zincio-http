//! QPACK fixture corpus: parsing and checks.
//!
//! Story files live in `tests/fixtures/qpack/stories/` — see the
//! `README.md` there for provenance and format. The decoder test replays
//! each story against a real decoder; the encoder test encodes the expected
//! headers with this crate's encoder and round-trips them through a
//! decoder. Gated on `--features h3`, which owns the QPACK module.

#![cfg(feature = "h3")]

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use serde_json::Value;
use zincio_http::qpack::{Decoder, Encoder};

const STORIES_DIR: &str = "tests/fixtures/qpack/stories";

#[derive(Debug)]
pub(crate) struct Story {
    pub(crate) table_capacity: u64,
    pub(crate) max_blocked_streams: usize,
    /// Deliver every field section before any encoder stream bytes (the
    /// `nghttp3/` stories set this to exercise blocked streams).
    pub(crate) delay_encoder_stream: bool,
    pub(crate) cases: Vec<Case>,
}

#[derive(Debug)]
pub(crate) struct Case {
    pub(crate) stream_id: u64,
    pub(crate) wire: Vec<u8>,
    /// Expected header list for field-section records; encoder records
    /// carry no headers.
    pub(crate) headers: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

/// All story files in the corpus, sorted for deterministic ordering.
pub(crate) fn story_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for dir in fs::read_dir(STORIES_DIR).unwrap() {
        let dir = dir.unwrap();
        if !dir.path().is_dir() {
            continue;
        }
        for file in fs::read_dir(dir.path()).unwrap() {
            let file = file.unwrap();
            if file.path().extension().is_some_and(|e| e == "json") {
                paths.push(file.path());
            }
        }
    }
    paths.sort();
    paths
}

/// Parses a story file into ordered records.
pub(crate) fn parse_story(path: &Path) -> Story {
    let text = fs::read_to_string(path).expect("read story file");
    let json: Value = serde_json::from_str(&text).expect("parse story json");
    let cases = json
        .get("cases")
        .and_then(Value::as_array)
        .expect("story cases is an array");
    assert!(!cases.is_empty(), "story {} has no cases", path.display());

    let table_capacity = json
        .get("table_capacity")
        .and_then(Value::as_u64)
        .expect("story table_capacity");
    let max_blocked_streams = json
        .get("max_blocked_streams")
        .and_then(Value::as_u64)
        .expect("story max_blocked_streams");

    let mut parsed = Vec::with_capacity(cases.len());
    for case in cases {
        let seqno = case.get("seqno").and_then(Value::as_u64).unwrap_or(0);
        let stream_id = case
            .get("stream_id")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("case {seqno}: missing stream_id"));
        let wire_hex = case
            .get("wire")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("case {seqno}: missing wire"));

        let headers = case.get("headers").map(|v| {
            let arr = v.as_array().expect("case headers is an array");
            arr.iter()
                .map(|pair| {
                    let pair = pair.as_array().expect("header is a [name, value] pair");
                    assert_eq!(pair.len(), 2, "case {seqno}: header pair has two elements");
                    let name = pair[0].as_str().expect("header name").to_owned();
                    let value = pair[1].as_str().expect("header value").to_owned();
                    (to_bytes(&name), to_bytes(&value))
                })
                .collect::<Vec<_>>()
        });

        parsed.push(Case {
            stream_id,
            wire: parse_hex(wire_hex),
            headers,
        });
    }

    Story {
        table_capacity,
        max_blocked_streams: usize::try_from(max_blocked_streams).expect("fits in usize"),
        delay_encoder_stream: json
            .get("delay_encoder_stream")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cases: parsed,
    }
}

/// Reverses the corpus's 1:1 code-point mapping of opaque bytes.
fn to_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

fn parse_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "wire hex string has even length"
    );
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = hexval(pair[0]);
            let lo = hexval(pair[1]);
            (hi << 4) | lo
        })
        .collect()
}

#[inline]
fn hexval(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit {b:#x}"),
    }
}

/// Replays a story against a decoder, in record order.
///
/// Encoder-stream records are fed via `feed_encoder_stream`; field-section
/// records via `decode_block`. A section whose Required Insert Count has not
/// been reached is parked and decoded when a later encoder record unblocks
/// it. With `delay_encoder_stream` all sections are delivered before any
/// encoder bytes, so every dynamic reference blocks first (record
/// interleaving in `nghttp3/` stories exercises this).
fn replay_decode(path: &Path, story: &Story) {
    let mut decoder = Decoder::new(story.table_capacity, story.max_blocked_streams);
    let mut parked: VecDeque<Case> = VecDeque::new();
    let mut encoder_records: Vec<&[u8]> = Vec::new();

    for (case_idx, case) in story.cases.iter().enumerate() {
        if case.stream_id == 0 {
            if story.delay_encoder_stream {
                encoder_records.push(&case.wire);
            } else {
                feed_encoder(&mut decoder, path, case_idx, &case.wire, &mut parked);
            }
            continue;
        }

        match decoder
            .decode_block(&case.wire, case.stream_id, 0)
            .unwrap_or_else(|e| panic!("stream {}: decode error: {e:?}", case.stream_id))
        {
            Some(headers) => {
                let expected: Vec<(Bytes, Bytes)> = case
                    .headers
                    .as_ref()
                    .expect("decoded section has expected headers")
                    .iter()
                    .map(|(name, value)| {
                        (Bytes::copy_from_slice(name), Bytes::copy_from_slice(value))
                    })
                    .collect();
                assert_headers(&headers, &expected);
            }
            None => parked.push_back(Case {
                stream_id: case.stream_id,
                wire: case.wire.clone(),
                headers: case.headers.clone(),
            }),
        }
    }

    if story.delay_encoder_stream {
        for (i, wire) in encoder_records.iter().enumerate() {
            feed_encoder(&mut decoder, path, i, wire, &mut parked);
        }
    }

    assert!(
        parked.is_empty(),
        "{} sections still blocked at end of story",
        parked.len()
    );
}

fn feed_encoder(
    decoder: &mut Decoder,
    path: &Path,
    case_idx: usize,
    wire: &[u8],
    parked: &mut VecDeque<Case>,
) {
    for section in decoder.feed_encoder_stream(wire).unwrap_or_else(|e| {
        panic!(
            "story {} case {case_idx}: encoder stream error: {e:?}",
            path.display()
        )
    }) {
        let parked_case = parked.pop_front().unwrap_or_else(|| {
            panic!(
                "decoder unblocked stream {} but no section was parked",
                section.stream_id
            )
        });
        assert_eq!(
            section.stream_id, parked_case.stream_id,
            "unblocked section on stream {} does not match parked stream {}",
            section.stream_id, parked_case.stream_id
        );
        let expected: Vec<(Bytes, Bytes)> = parked_case
            .headers
            .expect("parked section has expected headers")
            .iter()
            .map(|(name, value)| (Bytes::copy_from_slice(name), Bytes::copy_from_slice(value)))
            .collect();
        assert_headers(&section.headers, &expected);
    }
}

fn assert_headers(actual: &[(Bytes, Bytes)], expected: &[(Bytes, Bytes)]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "header count: got {actual:?} expected {expected:?}"
    );
    for ((name, value), (exp_name, exp_value)) in actual.iter().zip(expected) {
        assert_eq!(name.as_ref(), exp_name.as_ref(), "header name");
        assert_eq!(value.as_ref(), exp_value.as_ref(), "header value");
    }
}

/// Encodes every field section of a story with this crate's encoder and
/// round-trips the result through a decoder, comparing to the expected
/// headers. The decoder advertises the story capacity; the encoder warms its
/// dynamic table to that capacity first.
fn replay_encode(story: &Story) {
    let mut encoder = Encoder::new(story.table_capacity, false);
    let mut decoder = Decoder::new(story.table_capacity, story.max_blocked_streams);
    if let Some(bytes) = encoder.set_capacity(story.table_capacity) {
        decoder
            .feed_encoder_stream(&bytes)
            .expect("set-capacity accepted");
    }

    let mut parked: VecDeque<(u64, Vec<(Bytes, Bytes)>)> = VecDeque::new();

    for case in &story.cases {
        let Some(headers) = &case.headers else {
            continue;
        };
        let headers: Vec<(Bytes, Bytes)> = headers
            .iter()
            .map(|(name, value)| (Bytes::copy_from_slice(name), Bytes::copy_from_slice(value)))
            .collect();
        let encoded = encoder.encode_section(0, &headers);
        for section in decoder
            .feed_encoder_stream(&encoded.encoder_stream)
            .expect("encoder stream accepted")
        {
            let (stream_id, expected) = parked.pop_front().expect("parked section unblocked");
            assert_eq!(section.stream_id, stream_id, "unblocked stream mismatch");
            assert_headers(&section.headers, &expected);
        }
        match decoder
            .decode_block(&encoded.block, case.stream_id, 0)
            .expect("our own block decodes")
        {
            Some(decoded) => assert_headers(&decoded, &headers),
            None => parked.push_back((case.stream_id, headers)),
        }
    }
}

#[test]
fn corpus_parses() {
    let paths = story_paths();
    assert!(!paths.is_empty(), "no story files found");
    for path in &paths {
        let story = parse_story(path);
        assert!(
            story.cases.iter().any(|c| c.stream_id != 0),
            "{}: story has no field-section record",
            path.display()
        );
    }
}

#[test]
fn corpus_decodes() {
    for path in story_paths() {
        replay_decode(&path, &parse_story(&path));
    }
}

#[test]
fn corpus_blocks_some_sections() {
    // The `delay_encoder_stream` stories deliver every field section before
    // any encoder stream bytes, so every dynamic reference must block first.
    let mut blocked_any = false;
    for path in story_paths() {
        let story = parse_story(&path);
        if !story.delay_encoder_stream {
            continue;
        }
        let mut decoder = Decoder::new(story.table_capacity, story.max_blocked_streams);
        let mut parked = 0usize;
        for case in &story.cases {
            if case.stream_id == 0 {
                continue;
            }
            if decoder
                .decode_block(&case.wire, case.stream_id, 0)
                .unwrap()
                .is_none()
            {
                parked += 1;
            }
        }
        assert!(parked > 0, "{}: no section blocked", path.display());
        blocked_any = true;
    }
    assert!(blocked_any, "no delayed-encoder-stream stories found");
}

#[test]
fn corpus_encodes_round_trips() {
    for path in story_paths() {
        replay_encode(&parse_story(&path));
    }
}
