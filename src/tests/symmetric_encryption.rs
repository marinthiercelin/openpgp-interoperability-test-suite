use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::types::SymmetricAlgorithm;

use crate::{
    OpenPGP,
    Data,
    Result,
    data,
    templates::Report,
    tests::{
        Test,
        TestMatrix,
        ConsumerTest,
        asymmetric_encryption::EncryptDecryptRoundtrip,
    },
};

const CIPHERS: &[SymmetricAlgorithm] = {
    use openpgp::types::SymmetricAlgorithm::*;
    &[
        IDEA, TripleDES, CAST5, Blowfish,
        AES128, AES192, AES256,
        Twofish,
        Camellia128, Camellia192, Camellia256,
    ]
};

/// Tests support for symmetric encryption algorithms.
struct SymmetricEncryptionSupport {
}

impl SymmetricEncryptionSupport {
    pub fn new() -> Result<SymmetricEncryptionSupport> {
        Ok(SymmetricEncryptionSupport {
        })
    }

    fn fallback(recipient: &openpgp::serialize::stream::Recipient,
                cipher: SymmetricAlgorithm, msg: Data)
                -> Result<(String, Data)>
    {
        match (&recipient.keyid().to_hex()[..], cipher, msg) {
            ("7C2FAA4DF93C37B2", SymmetricAlgorithm::IDEA, _) =>
                Ok((cipher.to_string(),
                    data::message("7C2FAA4DF93C37B2.IDEA.pgp").into())),
            _ =>
                Err(failure::format_err!(
                    "Unsupported symmetric algorithm: {:?}", cipher))
        }
    }
}

impl Test for SymmetricEncryptionSupport {
    fn title(&self) -> String {
        "Symmetric Encryption Algorithm support".into()
    }

    fn description(&self) -> String {
        "This tests support for the different symmetric encryption algorithms \
         using Sequoia to generate the artifacts.".into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for SymmetricEncryptionSupport {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let mut t = Vec::new();

        for &cipher in CIPHERS {
            let mut b = Vec::new();

            {
                let recipient: Recipient =
                    cert.keys().with_policy(super::P, None)
                    .for_transport_encryption()
                    .nth(0).unwrap().key().into();
                let msg = format!("Encrypted using {:?}.", cipher)
                    .into_bytes().into_boxed_slice();
                let stack = Message::new(&mut b);
                let stack = match
                    Encryptor::for_recipient(stack, recipient).sym_algo(cipher)
                        .build()
                {
                    Ok(stack) => stack,
                    Err(_) => {
                        let recipient: Recipient =
                            cert.keys().with_policy(super::P, None)
                            .for_transport_encryption()
                            .nth(0).unwrap().key().into();
                        // Cipher is not supported by Sequoia, look
                        // for a fallback.
                        match Self::fallback(&recipient, cipher, msg) {
                            Ok(r) => t.push(r),
                            Err(e) => eprintln!("\r{}", e),
                        }
                        continue;
                    },
                };
                let mut stack = LiteralWriter::new(stack).build()?;
                stack.write_all(&msg)?;
                stack.finalize()?;
            }

            t.push((format!("{:?}", cipher), b.into_boxed_slice()));
        }

        Ok(t)
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    use openpgp::types::SymmetricAlgorithm::*;
    use openpgp::types::AEADAlgorithm::*;

    report.add_section("Symmetric Encryption");
    report.add(Box::new(SymmetricEncryptionSupport::new()?));

    for &cipher in CIPHERS {
        report.add(Box::new(
            EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         cipher),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [{:?}].", cipher),
                openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), cipher, None)?));
    }

    for &aead_algo in &[EAX, OCB] {
        report.add(Box::new(
            EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         aead_algo),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [AES256], \
                          AEAD algorithm preference [{:?}].", aead_algo),
                openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), AES256,
                Some(aead_algo))?));
    }

    Ok(())
}
