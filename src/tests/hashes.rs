use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::types::HashAlgorithm;

use crate::{
    Result,
    data,
    tests::TestPlan,
    tests::{
        detached_signatures::DetachedSignVerifyRoundtrip,
    },
};

pub const HASHES: &[HashAlgorithm] = {
    use HashAlgorithm::*;
    &[
        MD5, SHA1, RipeMD,
        SHA256, SHA384, SHA512, SHA224,
    ]
};

mod shattered;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Hash Algorithms");

    for &hash in HASHES {
        plan.add(Box::new(
            DetachedSignVerifyRoundtrip::with_hash(
                &format!("Detached Sign-Verify roundtrip with key 'Bob', {:?}",
                         hash),
                &format!("Detached Sign-Verify roundtrip using the 'Bob' key \
                          from draft-bre-openpgp-samples-00, modified with the \
                          hash algorithm preference [{:?}].", hash),
                openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
                crate::tests::MESSAGE.to_vec().into(), hash)?));
    }
    plan.add(Box::new(shattered::Shattered::new()?));

    Ok(())
}
