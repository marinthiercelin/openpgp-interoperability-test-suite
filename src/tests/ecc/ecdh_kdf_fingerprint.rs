use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests whether implementations are willing to unwrap session keys
/// using the recipient's primary key fingerprint.
pub struct ECDHKDFFingerprint {
}

impl ECDHKDFFingerprint {
    pub fn new() -> Result<ECDHKDFFingerprint> {
        Ok(ECDHKDFFingerprint {})
    }
}

impl Test for ECDHKDFFingerprint {
    fn title(&self) -> String {
        "ECDH KDF using recipient fingerprint".into()
    }

    fn description(&self) -> String {
        "Tests whether implementations are willing to unwrap session keys \
         using the recipient's primary key fingerprint.".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Key".into(), data::certificate("alice-secret.pgp").into()),
        ]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ECDHKDFFingerprint {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        // The test cases are produced with a hacked up version of
        // sequoia-openpgp 1.9.
        Ok(vec![
            ("KDF the subkey's fingerprint".into(),
             data::message("alice-kdf-subkey.pgp").into(),
             Some(Ok("Base case".into()))),
            ("KDF the primary key's fingerprint".into(),
             data::message("alice-kdf-primary.pgp").into(),
             None),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        Ok(pgp.sop().decrypt()
           .key(data::certificate("alice-secret.pgp"))
           .ciphertext(artifact)?.1)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == crate::tests::MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!("Expected {:?}, got {:?}",
                                        crate::tests::MESSAGE,
                                        artifact)))
        }
    }
}
