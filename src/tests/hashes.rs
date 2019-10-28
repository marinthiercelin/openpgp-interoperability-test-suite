use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        ProducerConsumerTest,
        detached_signature::DetachedSignVerifyRoundtrip,
    },
};

pub fn run(report: &mut Report, implementations: &[Box<dyn OpenPGP>])
           -> Result<()> {
    use openpgp::constants::HashAlgorithm::*;

    report.add_section("Hash Algorithms")?;

    for &hash in &[MD5, SHA1, RipeMD, SHA256, SHA384, SHA512, SHA224] {
        report.add(
            DetachedSignVerifyRoundtrip::with_hash(
                &format!("Detached Sign-Verify roundtrip with key 'Bob', {:?}",
                         hash),
                &format!("Detached Sign-Verify roundtrip using the 'Bob' key \
                          from draft-bre-openpgp-samples-00, modified with the \
                          hash algorithm preference [{:?}].", hash),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), hash)?
            .run(implementations)?)?;
    }

    Ok(())
}
