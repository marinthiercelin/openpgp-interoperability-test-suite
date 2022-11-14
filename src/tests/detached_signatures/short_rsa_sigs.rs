//! The files used in this test are data/short-rsa-sigs, generated
//! using example/short-rsa.rs.

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        TestMatrix,
    },
};

/// Explores whether implementations properly handle improbably short
/// RSA signatures.
pub struct ShortRSASigs {
}

impl ShortRSASigs {
    pub fn new() -> Result<ShortRSASigs> {
        Ok(ShortRSASigs {
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for ShortRSASigs {
    fn title(&self) -> String {
        "Improbably short RSA signatures".into()
    }

    fn description(&self) -> String {
        format!("<p>
Explores whether implementations properly handle improbably short RSA
signatures.  RSA signatures are of the same size as the signing key's
modulus.  However, OpenPGP will strip leading zeros, so we can have
\"short\" signatures with implementations either having to pad the
signature again, or omitting RFC 3447's length check.
</p>
<p>The signatures are over the string {:?} made using Bob's key.</p>
", String::from_utf8_lossy(crate::tests::MESSAGE))
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }

    fn tags(&self) -> std::collections::BTreeSet<&'static str> {
        ["verify-only"].iter().cloned().collect()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ShortRSASigs {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        const PREFIX: &str = "short-rsa-sigs/";
        let mut sigs = crate::data::files()
            .filter(|(name, _)| name.starts_with(PREFIX))
            .map(|(name, sig)|
                 (name[PREFIX.len()..name.len() - 8].parse::<usize>()
                  .expect("a number"),
                  sig))
            .filter(|(bits, _)| bits % 8 == 0)
            .map(|(bits, sig)|
                 (format!("{} bit signature", bits),
                  sig.to_vec().into(),
                  Some(Ok("Interoperability concern".into()))))
            .collect::<Vec<_>>();
        sigs.reverse();
        Ok(sigs)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.sop().verify()
            .cert(data::certificate("bob.pgp"))
            .signatures(artifact)
            .data_raw(crate::tests::MESSAGE)
    }
}
