use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::{S2K, SessionKey},
    fmt::hex,
    packet::prelude::*,
    serialize::{Serialize, stream::*},
    types::*,
};
use crate::{
    OpenPGP,
    Data,
    Result,
    tests::{
        PASSWORD,
        MESSAGE,
        Expectation,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests support for S2K mechanisms in the context of symmetrically
/// encrypted messages.
pub struct S2KSupport {
}

impl S2KSupport {
    pub fn new() -> Result<S2KSupport> {
        Ok(S2KSupport {
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for S2KSupport {
    fn title(&self) -> String {
        "S2K mechanisms".into()
    }

    fn description(&self) -> String {
        format!(
            "Tests support for S2K mechanisms in the context of symmetrically \
             encrypted messages.  Encrypts a message using the password {:?} \
             using different S2K mechanisms, and tries to decrypt it.",
            crate::tests::PASSWORD)
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for S2KSupport {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let mut t = Vec::new();

        // Base case.
        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;
        let message = Encryptor::with_passwords(
            message, Some(PASSWORD)).build()?;
        let mut w = LiteralWriter::new(message).build()?;
        w.write_all(MESSAGE)?;
        w.finalize()?;
        t.push(("Base case".into(), sink.into(),
                Some(Ok("Interoperability concern".into()))));

        let cipher = SymmetricAlgorithm::default();
        let hash = HashAlgorithm::SHA256;
        let salt = b"salziger";
        #[allow(deprecated)]
        for (label, s2k) in vec![
            ("simple", S2K::Simple { hash, }),
            ("salted", S2K::Salted { hash, salt: salt.clone(), }),
            ("iterated min",
             S2K::Iterated { hash, salt: salt.clone(), hash_bytes: 1024, }),
            ("iterated max",
             S2K::Iterated { hash, salt: salt.clone(), hash_bytes: 0x3e00000, }),
        ] {
            // First, SKESK with encrypted session key.
            let sk = SessionKey::new(cipher.key_size()?);
            let skesk = SKESK4::with_password(
                cipher, // Payload cipher.
                cipher,
                s2k.clone(),
                &sk,
                &PASSWORD.into())?;

            let mut sink = Vec::new();
            let message = Message::new(&mut sink);
            let mut message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("With password {:?}", PASSWORD))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;
            Packet::from(skesk).serialize(&mut message)?;
            let message = Encryptor::with_session_key(
                message, cipher, sk)?.build()?;
            let mut w = LiteralWriter::new(message).build()?;
            w.write_all(MESSAGE)?;
            w.finalize()?;
            t.push((format!("{} + esk", label),
                    sink.into(),
                    None));

            // Now, a SKESK w/o session key where the sk is derived
            // from the S2K.
            let sk = s2k.derive_key(&PASSWORD.into(), cipher.key_size()?)?;
            let skesk = SKESK4::new(cipher, s2k, None)?;

            let mut sink = Vec::new();
            let message = Message::new(&mut sink);
            let mut message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("With password {:?}", PASSWORD))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;
            Packet::from(skesk).serialize(&mut message)?;
            let message = Encryptor::with_session_key(
                message, cipher, sk)?.build()?;
            let mut w = LiteralWriter::new(message).build()?;
            w.write_all(MESSAGE)?;
            w.finalize()?;
            t.push((format!("{} w/o esk", label),
                    sink.into(),
                    None));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data>
    {
        pgp.sop()
            .decrypt()
            .with_password(PASSWORD)
            .ciphertext(artifact)
            .map(|(_verifications, plaintext)| plaintext)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                MESSAGE, artifact))
        }
    }
}
