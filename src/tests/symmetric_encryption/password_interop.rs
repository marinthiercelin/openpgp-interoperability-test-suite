use crate::{
    Data,
    OpenPGP,
    Result,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ProducerConsumerTest,
    },
};

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct PasswordEncryptionInterop {
}

impl PasswordEncryptionInterop {
    pub fn new() -> Result<PasswordEncryptionInterop> {
        Ok(PasswordEncryptionInterop {})
    }
}

impl Test for PasswordEncryptionInterop {
    fn title(&self) -> String {
        "Password-based encryption".into()
    }

    fn description(&self) -> String {
        format!("Encrypts a message using the password {:?}, \
                 and tries to decrypt it.", crate::tests::PASSWORD)
    }

    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for PasswordEncryptionInterop {
    fn produce(&self, pgp: &dyn OpenPGP)
               -> Result<Data> {
        pgp.sop().encrypt()
            .with_password(crate::tests::PASSWORD)
            .plaintext(crate::tests::MESSAGE)
    }

    fn consume(&self,
               _producer: &dyn OpenPGP,
               consumer: &dyn OpenPGP,
               artifact: &[u8])
               -> Result<Data> {
        consumer.sop()
            .decrypt()
            .with_password(crate::tests::PASSWORD)
            .ciphertext(artifact)
            .map(|(_verifications, plaintext)| plaintext)
    }

    fn check_consumer(&self, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == crate::tests::MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                crate::tests::MESSAGE, artifact))
        }
    }

    fn expectation(&self) -> Option<Expectation> {
        Some(Ok("Interoperability concern.".into()))
    }
}
