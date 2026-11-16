//! Shared helpers for the header-compression fixture corpora.

use std::{fs, path::PathBuf};

/// All story files under `root`, sorted for deterministic ordering.
pub fn story_paths(root: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for dir in fs::read_dir(root).unwrap() {
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

pub fn parse_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "wire hex string has even length"
    );
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (hexval(pair[0]) << 4) | hexval(pair[1]))
        .collect()
}

fn hexval(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit {b:#x}"),
    }
}
