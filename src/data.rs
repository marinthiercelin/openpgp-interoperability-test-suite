//! Test data for Sequoia.
//!
//! This module includes the test data from `data` in a structured
//! way.

use std::collections::BTreeMap;

lazy_static::lazy_static! {
    static ref FILES: BTreeMap<&'static str, &'static [u8]> = {
        let mut m: BTreeMap<&'static str, &'static [u8]> =
            Default::default();

        macro_rules! add {
            ( $key: expr, $path: expr ) => {
                m.insert($key, include_bytes!($path))
            }
        }
        include!(concat!(env!("OUT_DIR"), "/data.index.rs.inc"));

        // Sanity checks.
        assert!(m.contains_key("certificates/alice.pgp"));
        assert!(m.contains_key("certificates/bob-secret.pgp"));
        m
    };
}

/// Returns an iterator over all files.
pub fn files() -> impl Iterator<Item = (&'static str, &'static [u8])> {
    FILES.iter().map(|(k, v)| (*k, *v))
}

/// Returns the content of the given file below `data`.
pub fn file(name: &str) -> Option<&'static [u8]> {
    FILES.get(name).cloned()
}

/// Returns the content of the given file below `data/certificates`.
pub fn certificate(name: &str) -> &'static [u8] {
    file(&format!("certificates/{}", name))
        .unwrap_or_else(|| panic!("No such certificate {:?}", name))
}

/// Returns the content of the given file below `data/messages`.
pub fn message(name: &str) -> &'static [u8] {
    file(&format!("messages/{}", name))
        .unwrap_or_else(|| panic!("No such message {:?}", name))
}
