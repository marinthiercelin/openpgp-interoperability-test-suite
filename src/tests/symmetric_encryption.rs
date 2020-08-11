use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    PacketPile,
    packet::prelude::*,
    parse::Parse,
    serialize::SerializeInto,
    types::SymmetricAlgorithm,
};
use crate::{
    OpenPGP,
    Data,
    Result,
    data,
    templates::Report,
    tests::{
        Expectation,
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
                -> Result<(String, Data, Option<Expectation>)>
    {
        match (&format!("{:X}", recipient.keyid())[..], cipher, msg) {
            ("7C2FAA4DF93C37B2", SymmetricAlgorithm::IDEA, _) =>
                Ok((cipher.to_string(),
                    data::message("7C2FAA4DF93C37B2.IDEA.pgp").into(),
                    None)),
            _ =>
                Err(anyhow::anyhow!(
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

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for SymmetricEncryptionSupport {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let mut t = Vec::new();

        for &cipher in CIPHERS {
            use SymmetricAlgorithm::*;
            let expectation = match cipher {
                // Even though this is a MUST, it should better be avoided.
                TripleDES =>
                    None, // Don't judge.
                AES128 =>
                    Some(Ok("AES-128 is a MUST according to RFC4880bis8.".into())),
                AES192 | AES256 =>
                    Some(Ok("AES should be supported".into())),
                _ => None,
            };

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
                    Encryptor::for_recipients(stack, vec![recipient])
                        .symmetric_algo(cipher)
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

            t.push(
                (format!("{:?}", cipher), b.into_boxed_slice(), expectation));
        }

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.decrypt(data::certificate("bob-secret.pgp"), artifact)
    }
}

/// Tests support for symmetrically encrypted integrity protected packets.
struct SEIPSupport {
}

impl SEIPSupport {
    pub fn new() -> Result<SEIPSupport> {
        Ok(SEIPSupport {
        })
    }
}

impl Test for SEIPSupport {
    fn title(&self) -> String {
        "SEIP packet support".into()
    }

    fn description(&self) -> String {
        "This tests support for the Symmetrically Encrypted Integrity \
         Protected Data Packet (Tag 18) and verifies that modifications to \
         the ciphertext are detected.  It uses Sequoia to generate the \
         artifacts.".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for SEIPSupport {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        // The tests.
        let mut t = Vec::new();
        // Makes tests.
        let make =
            |test: &str, message: &[u8], expectation: Option<Expectation>|
            -> Result<(String, Data, Option<Expectation>)>
        {
            let mut buf = Vec::new();
            {
                use openpgp::armor;
                let mut w =
                    armor::Writer::new(&mut buf, armor::Kind::Message)?;
                w.write_all(message)?;
                w.finalize()?;
            }
            Ok((test.into(), buf.into(), expectation))
        };

        // Use the RSA key to increase compatibility.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;
        let recipient: Recipient =
            cert.keys().with_policy(super::P, None)
            .for_transport_encryption()
            .nth(0).unwrap().key().into();

        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Encryptor::for_recipients(message, vec![recipient])
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(b"Encrypted using SEIP + MDC.")?;
        message.finalize()?;

        // The base case as-is.
        t.push(make("Base case", &buf,
                    Some(Ok("SEIP is a MUST according to RFC4880.".into())))?);

        // Shave off the MDC packet.
        let mut packets = PacketPile::from_bytes(&buf)?;
        if let Some(Packet::SEIP(seip)) = packets.path_ref_mut(&[1]) {
            let tampered = if let Body::Unprocessed(ciphertext) = seip.body() {
                Body::Unprocessed(ciphertext[..ciphertext.len() - 22].into())
            } else {
                panic!("Unexpected packet body");
                // XXX: panic!("Unexpected packet body: {:?}", seip.body());
            };
            seip.set_body(tampered);
        } else {
            panic!("Unexpected packet at [1]: {:?}", packets.path_ref(&[1]));
        }
        t.push(make("Missing MDC", &packets.to_vec()?,
                    Some(Err("Missing MDC must abort processing.".into())))?);

        // Downgrade to SED packet.
        let mut packets = PacketPile::from_bytes(&buf)?;
        let mut sed = Unknown::new(Tag::SED,
                                   anyhow::anyhow!("SED not supported"));
        if let Some(Packet::SEIP(seip)) = packets.path_ref(&[1]) {
            if let Body::Unprocessed(ciphertext) = seip.body() {
                sed.set_body(ciphertext[..ciphertext.len() - 22].into());
            } else {
                panic!("Unexpected packet body");
                // XXX: panic!("Unexpected packet body: {:?}", seip.body());
            }
        } else {
            panic!("Unexpected packet at [1]: {:?}", packets.path_ref(&[1]));
        }
        packets.replace(&[1], 1, vec![sed.into()])?;
        t.push(make("Downgrade to SED", &packets.to_vec()?,
                    Some(Err("Security concern: Downgrade must be prevented."
                             .into())))?);

        // Tamper with the literal data.
        let mut packets = PacketPile::from_bytes(&buf)?;
        if let Some(Packet::SEIP(seip)) = packets.path_ref_mut(&[1]) {
            let tampered = if let Body::Unprocessed(ciphertext) = seip.body() {
                let mut body = ciphertext.clone();
                let l = body.len();
                body[l - 23] = 0;
                Body::Unprocessed(body)
            } else {
                panic!("Unexpected packet body");
                // XXX: panic!("Unexpected packet body: {:?}", seip.body());
            };
            seip.set_body(tampered);
        } else {
            panic!("Unexpected packet at [1]: {:?}", packets.path_ref(&[1]));
        }
        t.push(make("Tampered ciphertext", &packets.to_vec()?,
                    Some(Err("Security concern: Tampering must be prevented."
                             .into())))?);

        // Tamper with the MDC.
        let mut packets = PacketPile::from_bytes(&buf)?;
        if let Some(Packet::SEIP(seip)) = packets.path_ref_mut(&[1]) {
            let tampered = if let Body::Unprocessed(ciphertext) = seip.body() {
                let mut body = ciphertext.clone();
                let l = body.len();
                body[l - 1] = 0;
                Body::Unprocessed(body)
            } else {
                panic!("Unexpected packet body");
                // XXX: panic!("Unexpected packet body: {:?}", seip.body());
            };
            seip.set_body(tampered);
        } else {
            panic!("Unexpected packet at [1]: {:?}", packets.path_ref(&[1]));
        }
        t.push(make("Tampered MDC", &packets.to_vec()?,
                    Some(Err("Security concern: Tampering must be prevented."
                             .into())))?);

        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
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

    report.add(Box::new(SEIPSupport::new()?));

    Ok(())
}
