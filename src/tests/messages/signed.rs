use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::*,
    crypto::SessionKey,
    fmt::hex,
    packet::prelude::*,
    PacketPile,
    parse::Parse,
    serialize::{Serialize, SerializeInto, stream::*},
    types::*,
};
use crate::{
    OpenPGP,
    Data,
    Result,
    data,
    tests::{
        Expectation,
        TestMatrix,
        ConsumerTest,
    },
};

const MESSAGE: &[u8] = b"Hello\r\nWorld!\n";
const EXPECT_TWO_SIGS_AT: usize = 15;

/// Tests support for signed and optionally encrypted messages.
pub struct Signed {
    encrypted: bool,
    bobs_fp: openpgp::Fingerprint,
    annes_fp: openpgp::Fingerprint,
    annes_key: Data,
    annes_cert: Data,
}

impl Signed {
    pub fn new(encrypted: bool) -> Result<Signed> {
        let (anne, _rev) =
            CertBuilder::general_purpose(CipherSuite::RSA3k,
                                         Some("anne@example.org"))
            .generate()?;
        let annes_key = anne.as_tsk().armored().to_vec()?.into();
        let annes_cert = anne.armored().to_vec()?.into();
        let annes_fp = anne.fingerprint();
        let bobs_fp = openpgp::Cert::from_bytes(
            data::certificate("bob.pgp"))?.fingerprint();
        Ok(Signed {
            encrypted,
            bobs_fp,
            annes_fp,
            annes_key,
            annes_cert,
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for Signed {
    fn title(&self) -> String {
        if self.encrypted {
            "Signed (and encrypted) messages".into()
        } else {
            "Signed messages".into()
        }
    }

    fn description(&self) -> String {
        format!(
            "This is a collection of {} messages.  {}The \
             message is {:?}.  We vary signature type (binary, text), and \
             literal data format identifier.  Finally, we do the same with \
             both a binary signature and a text signature at the same time.  \
             To avoid deduplication, we sign the second signature using \
             Anne's key.",
            if self.encrypted { "signed-then-encrypted" } else { "signed" },
            if self.encrypted { "The messages are signed by and encrypted \
                                 to the same key.  " } else { "" },
            String::from_utf8_lossy(MESSAGE))
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Bob's Key".into(), data::certificate("bob-secret.pgp").into()),
            ("Anne's Cert".into(), self.annes_cert.clone()),
        ]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for Signed {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let mut t = Vec::new();

        // Use the RSA key to increase compatibility.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let recipient =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .nth(0).unwrap().key().clone();
        let signer =
            cert.keys().with_policy(crate::tests::P, None)
            .secret()
            .for_signing()
            .nth(0).unwrap().key().clone().into_keypair()?;

        // Base case binary.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;
            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };

        let message = Signer::new(message, signer.clone())
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Base case binary".into(),
                buf.into(),
                Some(Ok("Compatibility concern.".into()))));

        // Base case text.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };

        let message = Signer::with_template(
            message, signer.clone(),
            SignatureBuilder::new(SignatureType::Text))
            .build()?;
        let mut message = LiteralWriter::new(message)
            .format(DataFormat::Text)
            .build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Base case text".into(),
                buf.into(),
                Some(Ok("Compatibility concern.".into()))));

        // Different format fields, different signature types.
        for sig_type in vec![SignatureType::Binary, SignatureType::Text] {
            #[allow(deprecated)]
            for format in vec![
                DataFormat::Binary,
                DataFormat::Text,
                DataFormat::Unicode,
                DataFormat::MIME,
                DataFormat::from(b'l'),
                DataFormat::from(b'1'),
                DataFormat::from(0),
            ] {
                if (sig_type == SignatureType::Binary
                    && format == DataFormat::Binary)
                    || (sig_type == SignatureType::Text
                        && format == DataFormat::Text)
                {
                    continue; // These are the base cases.
                }

                let mut buf = Vec::new();
                let message = Message::new(&mut buf);
                let message = if self.encrypted {
                    let cipher = SymmetricAlgorithm::default();
                    let sk = SessionKey::new(cipher.key_size()?);

                    let message = Armorer::new(message)
                        .add_header("Comment",
                                    format!("Plaintext is {:?}",
                                            String::from_utf8_lossy(MESSAGE)))
                        .add_header("Comment",
                                    format!("Encrypted using {}", cipher))
                        .add_header("Comment",
                                    format!("Session key: {}", hex::encode(&sk)))
                        .build()?;

                    Encryptor::with_session_key(message, cipher, sk)?
                        .add_recipients(vec![&recipient])
                        .build()?
                } else {
                    Armorer::new(message).build()?
                };

                let message = Signer::with_template(
                    message, signer.clone(),
                    SignatureBuilder::new(sig_type))
                    .build()?;
                let mut message = LiteralWriter::new(message)
                    .format(format)
                    .build()?;
                message.write_all(MESSAGE)?;
                message.finalize()?;
                t.push((format!("{} sig / {:?}", sig_type, format),
                        buf.into(),
                        None));
            }
        }

        // Test an old-style signed message (SIG LIT).
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Signer::with_template(
            message, signer.clone(),
            SignatureBuilder::new(SignatureType::Binary))
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        let mut packets = PacketPile::from_bytes(&buf)?.into_children();
        let _bob_ops = packets.next().unwrap();
        let literal = packets.next().unwrap();
        let bob_sig = packets.next().unwrap();

        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };
        bob_sig.serialize(&mut message)?;
        literal.serialize(&mut message)?;
        message.finalize()?;
        t.push(("old-style: SIG LIT".into(), buf.into(), None));

        // Test messages with two signatures.
        assert_eq!(EXPECT_TWO_SIGS_AT, t.len());

        // Get Anne's signer.  We create one of the signatures using a
        // different signer to avoid verification deduplication.
        let annes_key =
            openpgp::Cert::from_bytes(&self.annes_key)?;
        let annes_signer =
            annes_key.keys().with_policy(crate::tests::P, None)
            .secret()
            .for_signing()
            .nth(0).unwrap().key().clone().into_keypair()?;

        // Base case, two similar signatures from the same issuer.
        //
        // Because of xxx we need to do that manually.  But, that
        // gives us the opportunity to construct the faulty case as
        // well.

        // First, make a binary sig.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Signer::with_template(
            message, signer.clone(),
            SignatureBuilder::new(SignatureType::Binary))
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        let mut packets = PacketPile::from_bytes(&buf)?.into_children();
        let bob_ops =
            if let Packet::OnePassSig(mut ops) = packets.next().unwrap() {
                // Clear the last flag because we want both signatures
                // to be over the data.
                ops.set_last(false);
                Packet::from(ops)
            } else {
                panic!("Unexpected packet")
            };
        let _literal = packets.next().unwrap();
        let bob_sig = packets.next().unwrap();

        // Then, make a binary sig using Anne's signer.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Signer::with_template(
            message, annes_signer.clone(),
            SignatureBuilder::new(SignatureType::Binary))
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        let mut packets = PacketPile::from_bytes(&buf)?.into_children();
        let anne_ops = packets.next().unwrap();
        let _literal = packets.next().unwrap();
        let anne_sig = packets.next().unwrap();

        // Now, compose them correctly (OPS_bob, OPS_anne, lit,
        // SIG_anne, SIG_bob).
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };

        bob_ops.serialize(&mut message)?;
        anne_ops.serialize(&mut message)?;
        let mut message = LiteralWriter::new(message)
            .format(DataFormat::Binary)
            .build()?;
        message.write_all(MESSAGE)?;
        let mut message = message.finalize_one()?.unwrap();
        anne_sig.serialize(&mut message)?;
        bob_sig.serialize(&mut message)?;
        message.finalize()?;
        t.push(("Base case two binary sigs".into(),
                buf.into(),
                Some(Ok("Compatibility concern.".into()))));

        // Now, compose them incorrectly (OPS_bob, OPS_anne, lit,
        // SIG_bob, SIG_anne).
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };

        bob_ops.serialize(&mut message)?;
        anne_ops.serialize(&mut message)?;
        let mut message = LiteralWriter::new(message)
            .format(DataFormat::Binary)
            .build()?;
        message.write_all(MESSAGE)?;
        let mut message = message.finalize_one()?.unwrap();
        bob_sig.serialize(&mut message)?;
        anne_sig.serialize(&mut message)?;
        message.finalize()?;
        t.push(("Two binary sigs, bad order".into(),
                buf.into(),
                None));

        // Now, we construct a binary and a text signature.  This
        // requires some acrobatics.

        // First, make a binary sig.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Signer::with_template(
            message, signer.clone(),
            SignatureBuilder::new(SignatureType::Binary))
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        let mut packets = PacketPile::from_bytes(&buf)?.into_children();
        let binary_ops =
            if let Packet::OnePassSig(mut ops) = packets.next().unwrap() {
                // Clear the last flag because we want both signatures
                // to be over the data.
                ops.set_last(false);
                Packet::from(ops)
            } else {
                panic!("Unexpected packet")
            };
        let _literal = packets.next().unwrap();
        let binary_sig = packets.next().unwrap();

        // Then, make a text sig using Anne's signer.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Signer::with_template(
            message, annes_signer.clone(),
            SignatureBuilder::new(SignatureType::Text))
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        let mut packets = PacketPile::from_bytes(&buf)?.into_children();
        let text_ops = packets.next().unwrap();
        let _literal = packets.next().unwrap();
        let text_sig = packets.next().unwrap();

        // Now, join them, mapping over the different literal formats.
        #[allow(deprecated)]
        for format in vec![
            DataFormat::Binary,
            DataFormat::Text,
            DataFormat::Unicode,
            DataFormat::MIME,
            DataFormat::from(b'l'),
            DataFormat::from(b'1'),
            DataFormat::from(0),
        ] {
            let mut buf = Vec::new();
            let message = Message::new(&mut buf);
            let mut message = if self.encrypted {
                let cipher = SymmetricAlgorithm::default();
                let sk = SessionKey::new(cipher.key_size()?);

                let message = Armorer::new(message)
                    .add_header("Comment",
                                format!("Plaintext is {:?}",
                                        String::from_utf8_lossy(MESSAGE)))
                    .add_header("Comment",
                                format!("Encrypted using {}", cipher))
                    .add_header("Comment",
                                format!("Session key: {}", hex::encode(&sk)))
                    .build()?;

                Encryptor::with_session_key(message, cipher, sk)?
                    .add_recipients(vec![&recipient])
                    .build()?
            } else {
                Armorer::new(message).build()?
            };

            binary_ops.serialize(&mut message)?;
            text_ops.serialize(&mut message)?;
            let mut message = LiteralWriter::new(message)
                .format(format)
                .build()?;
            message.write_all(MESSAGE)?;
            let mut message = message.finalize_one()?.unwrap();
            text_sig.serialize(&mut message)?;
            binary_sig.serialize(&mut message)?;
            message.finalize()?;
            t.push((format!("Binary & Text sig / {:?}", format),
                    buf.into(),
                    None));
        }

        // Test an mixed new and old-style signed message (SIG OPS LIT
        // SIG).  Bob makes the old-style signature.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };
        bob_sig.serialize(&mut message)?;
        anne_ops.serialize(&mut message)?;
        literal.serialize(&mut message)?;
        anne_sig.serialize(&mut message)?;
        message.finalize()?;
        t.push(("mix-style: SIG_b OPS_a LIT SIG_a".into(), buf.into(), None));

        // Test an mixed new and old-style signed message (OPS SIG LIT
        // SIG).  Bob makes the old-style signature.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = if self.encrypted {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);

            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;

            Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?
        } else {
            Armorer::new(message).build()?
        };
        anne_ops.serialize(&mut message)?;
        bob_sig.serialize(&mut message)?;
        literal.serialize(&mut message)?;
        anne_sig.serialize(&mut message)?;
        message.finalize()?;
        t.push(("mix-style: OPS_a SIG_b LIT SIG_a".into(), buf.into(), None));

        Ok(t)
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let (verifications, plaintext) = if self.encrypted {
            let mut decrypt = pgp.sop()
                .decrypt()
                .verify_cert(data::certificate("bob.pgp"));
            if i >= EXPECT_TWO_SIGS_AT {
                decrypt = decrypt.verify_cert(&self.annes_cert);
            }

            decrypt.key(data::certificate("bob-secret.pgp"))
                .ciphertext(artifact)?
        } else {
            let mut verify = pgp.sop()
                .inline_verify()
                .cert(data::certificate("bob.pgp"));
            if i >= EXPECT_TWO_SIGS_AT {
                verify = verify.cert(&self.annes_cert);
            }

            verify.message(artifact)?
        };

        if verifications.is_empty() {
            return Err(anyhow::anyhow!("No VERIFICATION emitted"));
        }
        let signer_fps =
            verifications.iter().map(|v| &v.cert).collect::<Vec<_>>();

        if i < EXPECT_TWO_SIGS_AT {
            if ! signer_fps.contains(&&self.bobs_fp) {
                return Err(
                    anyhow::anyhow!("No VERIFICATION output for Bob found"));
            }
        } else {
            if ! signer_fps.contains(&&self.bobs_fp) {
                return Err(
                    anyhow::anyhow!("No VERIFICATION output for Bob found"));
            }

            if ! signer_fps.contains(&&self.annes_fp) {
                return Err(
                    anyhow::anyhow!("No VERIFICATION output for Anne found"));
            }
        }

        Ok(plaintext)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8]) -> Result<()> {
        if &artifact[..] == MESSAGE {
            return Ok(());
        }

        // Some implementations normalize line endings when
        // verifying text signatures.  I guess that is okay too.
        if String::from_utf8_lossy(artifact).replace("\r\n", "\n")
            == String::from_utf8_lossy(MESSAGE).replace("\r\n", "\n")
        {
            return Ok(());
        }

        Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                            MESSAGE, artifact))
    }
}
