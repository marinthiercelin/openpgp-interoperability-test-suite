use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    plan::TestPlan,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests how implementations handle different EdDSA signature
/// encodings.
struct EdDSASignatureEncoding {
}

impl EdDSASignatureEncoding {
    pub fn new() -> Result<EdDSASignatureEncoding> {
        Ok(EdDSASignatureEncoding {
        })
    }
}

impl Test for EdDSASignatureEncoding {
    fn title(&self) -> String {
        "EdDSA signature encodings".into()
    }

    fn description(&self) -> String {
        "OpenPGP mandates that leading zeros are stripped when encoding MPIs. \
         This test tests whether leading zeros in S, and 0x40-prefixed R are \
         accepted.".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("alice.pgp").into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for EdDSASignatureEncoding {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let sig = openpgp::Packet::from_bytes(
            "-----BEGIN PGP SIGNATURE-----

             wnQEABYKACcFAl23GYsJEPIxVQxPR+OOFiEE64W7X6M6deFelE5j8jFVDE9H444A
             ANOWAPsHrQTUDtDyP3gr2KsdhX/iapwrO3HSLUD7X41YUasdygD4r6QGQxJXKfbR
             lpZFZ4otf72qcIzc82oZxaApG9L6Dg==
             =WUuG
             -----END PGP SIGNATURE-----")?;

        let mut sig_0 = sig.to_vec()?;
        sig_0[1] += 1; // Increase length of packet.
        sig_0[0x33] = 1; // Set length of R to 0x100 bit.
        sig_0[0x34] = 0;
        sig_0[0x55] = 1; // Set length of S to 0x100 bit.
        sig_0[0x56] = 0;
        sig_0.insert(0x57, 0); // Zero-pad S.
        assert_eq!(sig_0.len(), sig_0[1] as usize + 2 /* CTB + length */);

        let mut sig_0x40 = sig.to_vec()?;
        sig_0x40[1] += 1; // Increase length of packet.
        sig_0x40[0x33] = 1; // Set length of R to 0x107 bit.
        sig_0x40[0x34] = 7;
        sig_0x40.insert(0x35, 0x40); // 0x40-pad R.
        assert_eq!(sig_0x40.len(), sig_0x40[1] as usize + 2 /* CTB + length */);

        Ok(vec![
            ("MPI encoding".into(), sig.to_vec()?.into(),
             Some(Ok("MPI encoding must be supported.".into()))),
            ("S 0-padded".into(), sig_0.into(), None),
            ("R 0x40-prefixed".into(), sig_0x40.into(), None),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(data::certificate("alice.pgp"), b"huhu\n", artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Elliptic Curve Cryptography");
    plan.add(Box::new(EdDSASignatureEncoding::new()?));
    Ok(())
}
