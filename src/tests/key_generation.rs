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
    description: String,
    userids: HashSet<String>,
}

impl GenerateThenEncryptDecryptRoundtrip {
    pub fn new(title: &str, description: &str, userids: &[&str])
               -> GenerateThenEncryptDecryptRoundtrip {
        GenerateThenEncryptDecryptRoundtrip {
            title: title.into(),
            description: description.into(),
            userids: userids.iter().map(|u| u.to_string()).collect(),
        }
    }
}

impl Test for GenerateThenEncryptDecryptRoundtrip {
    fn title(&self) -> String {
        self.title.clone()
    }

    fn description(&self) -> String {
        self.description.clone()
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
        let tpk = openpgp::TPK::from_bytes(artifact)?;
        let userids: HashSet<String> = tpk.userids()
            .map(|uidb| {
                String::from_utf8_lossy(uidb.userid().value()).to_string()
            })
            .collect();

        let missing: Vec<&str> = self.userids.difference(&userids)
            .map(|s| &s[..]).collect();
        if ! missing.is_empty() {
            return Err(failure::format_err!("Missing userids: {:?}",
                                            missing));
        }

        let additional: Vec<&str> = userids.difference(&self.userids)
            .map(|s| &s[..]).collect();
        if ! additional.is_empty() {
            return Err(failure::format_err!("Additional userids: {:?}",
                                            additional));
        }

        Ok(())
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(&super::extract_cert(artifact)?,
                                     b"Hello, World!")?;
        pgp.decrypt(artifact, &ciphertext)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Key Generation");

    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip",
            "Default key generation, followed by the consumer using this \
             key to encrypt and then decrypt a message.",
            &["Bernadette <b@example.org>"])));
    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, 2 UIDs",
            "Default key generation with two UserIDs, followed by the consumer \
             using this key to encrypt and then decrypt a message.",
            &["Bernadette <b@example.org>", "Soo <s@example.org>"])));
    report.add(Box::new(
        GenerateThenEncryptDecryptRoundtrip::new(
            "Default key generation, encrypt-decrypt roundtrip, no UIDs",
            "Default key generation without UserIDs, followed by the consumer \
             using this key to encrypt and then decrypt a message.",
            &[])));
    Ok(())
}
