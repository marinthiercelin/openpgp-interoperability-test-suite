use std::collections::HashSet;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    OpenPGP,
    Data,
    Result,
    templates::Report,
    tests::{
        Test,
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

impl Test for GenerateThenEncryptDecryptRoundtrip {
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for GenerateThenEncryptDecryptRoundtrip {
    fn produce(&self, pgp: &mut OpenPGP)
               -> Result<Data> {
        let userids = self.userids.iter().map(|s| &s[..]).collect::<Vec<_>>();
        pgp.generate_key(&userids[..])
    }

    fn check_producer(&self, artifact: &[u8]) -> Result<()> {
        let tpk = openpgp::Cert::from_bytes(artifact)?;
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

        Ok(())
    }

    fn consume(&self, _: &mut OpenPGP, _: &[u8]) -> Result<Data> {
        unreachable!()
    }

    fn consume_with_producer(&self,
                             producer: &mut OpenPGP,
                             consumer: &mut OpenPGP,
                             artifact: &[u8])
               -> Result<Data> {
        let ciphertext = consumer.encrypt(&super::extract_cert(artifact)?,
                                          b"Hello, World!")?;
        producer.decrypt(artifact, &ciphertext)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Key Generation");

    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip",
            &["Bernadette <b@example.org>"])));
    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, 2 UIDs",
            &["Bernadette <b@example.org>", "Soo <s@example.org>"])));
    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, no UIDs",
            &[])));
    Ok(())
}
