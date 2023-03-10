use std::collections::HashSet;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    OpenPGP,
    Data,
    Result,
    tests::TestPlan,
    tests::{
        TestMatrix,
        ProducerConsumerTest,
    },
};

pub struct GenerateThenEncryptDecryptRoundtrip {
    title: String,
    userids: HashSet<String>,
}

impl GenerateThenEncryptDecryptRoundtrip {
    pub fn new(title: &str, userids: &[&str])
               -> GenerateThenEncryptDecryptRoundtrip {
        GenerateThenEncryptDecryptRoundtrip {
            title: title.into(),
            userids: userids.iter().map(|u| u.to_string()).collect(),
        }
    }
}

impl crate::plan::Runnable<TestMatrix> for GenerateThenEncryptDecryptRoundtrip {
    fn title(&self) -> String {
        self.title.clone()
    }

    fn description(&self) -> String {
        "This models key generation, distribution, and encrypted
        message exchange.  Generates a default key with the producer
        <i>P</i>, then extracts the certificate from the key and uses
        it to encrypt a message using the consumer <i>C</i>, and
        finally <i>P</i> to decrypt the message.".into()
    }

    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for GenerateThenEncryptDecryptRoundtrip {
    fn produce(&self, pgp: &dyn OpenPGP)
               -> Result<Data> {
        let userids = self.userids.iter().map(|s| &s[..]).collect::<Vec<_>>();
        pgp.generate_key(&userids[..])
    }

    fn check_producer(&self, artifact: Data) -> Result<Data> {
        let tpk = openpgp::Cert::from_bytes(&artifact)?;
        let userids: HashSet<String> = tpk.userids()
            .map(|uidb| {
                String::from_utf8_lossy(uidb.userid().value()).to_string()
            })
            .collect();

        let missing: Vec<&str> = self.userids.difference(&userids)
            .map(|s| &s[..]).collect();
        if ! missing.is_empty() {
            return Err(anyhow::anyhow!("Missing userids: {:?}",
                                            missing));
        }

        let additional: Vec<&str> = userids.difference(&self.userids)
            .map(|s| &s[..]).collect();
        if ! additional.is_empty() {
            return Err(anyhow::anyhow!("Additional userids: {:?}",
                                            additional));
        }

        Ok(artifact)
    }

    fn consume(&self,
               producer: &dyn OpenPGP,
               consumer: &dyn OpenPGP,
               artifact: &[u8])
               -> Result<Data> {
        let ciphertext = consumer.encrypt(&super::extract_cert(artifact)?,
                                          crate::tests::MESSAGE)?;
        producer.decrypt(artifact, &ciphertext)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Key Generation");

    plan.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip",
            &["Bernadette <b@example.org>"])));
    plan.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, 2 UIDs",
            &["Bernadette <b@example.org>", "Soo <s@example.org>"])));
    plan.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, no UIDs",
            &[])));
    Ok(())
}
