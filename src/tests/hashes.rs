use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    Result,
    data,
    templates::Report,
    tests::{
        detached_signature::DetachedSignVerifyRoundtrip,
    },
};

pub fn schedule(report: &mut Report) -> Result<()> {
    use openpgp::constants::HashAlgorithm::*;

    report.add_section("Hash Algorithms");

    for &hash in &[MD5, SHA1, RipeMD, SHA256, SHA384, SHA512, SHA224] {
        report.add(Box::new(
            DetachedSignVerifyRoundtrip::with_hash(
                &format!("Detached Sign-Verify roundtrip with key 'Bob', {:?}",
                         hash),
                &format!("Detached Sign-Verify roundtrip using the 'Bob' key \
                          from draft-bre-openpgp-samples-00, modified with the \
                          hash algorithm preference [{:?}].", hash),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), hash)?));
    }

    Ok(())
}
