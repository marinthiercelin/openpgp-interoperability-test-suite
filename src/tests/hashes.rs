use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    Result,
    data,
    plan::TestPlan,
    tests::{
        detached_signatures::DetachedSignVerifyRoundtrip,
    },
};

mod shattered;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    use openpgp::types::HashAlgorithm::*;

    plan.add_section("Hash Algorithms");

    for &hash in &[MD5, SHA1, RipeMD, SHA256, SHA384, SHA512, SHA224] {
        plan.add(Box::new(
            DetachedSignVerifyRoundtrip::with_hash(
                &format!("Detached Sign-Verify roundtrip with key 'Bob', {:?}",
                         hash),
                &format!("Detached Sign-Verify roundtrip using the 'Bob' key \
                          from draft-bre-openpgp-samples-00, modified with the \
                          hash algorithm preference [{:?}].", hash),
                openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into(), hash)?));
    }
    plan.add(Box::new(shattered::Shattered::new()?));

    Ok(())
}
