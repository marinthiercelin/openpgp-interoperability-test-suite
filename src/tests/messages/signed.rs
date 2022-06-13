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
const EXPECT_TWO_SIGS_AT: usize = 14;

/// Tests support for malformed messages.
pub struct Signed {
    annes_key: Data,
    annes_cert: Data,
}

impl Signed {
    pub fn new() -> Result<Signed> {
        let (anne, _rev) =
            CertBuilder::general_purpose(CipherSuite::RSA3k,
                                         Some("anne@example.org"))
            .generate()?;
        let annes_key = anne.as_tsk().armored().to_vec()?.into();
        let annes_cert = anne.armored().to_vec()?.into();
        Ok(Signed {
            annes_key,
            annes_cert,
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for Signed {
    fn title(&self) -> String {
        "Signed messages".into()
    }

    fn description(&self) -> String {
        format!(
            "This is a collection of signed-then-encrypted messages.  The \
             messages are signed by and encrypted to the same key.  The \
             message is {:?}.  We vary signature type (binary, text), and \
             literal data format identifier.  Finally, we do the same with \
             both a binary signature and a text signature at the same time.  \
             To avoid deduplication, we sign the second signature using \
             Anne's key.",
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
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let message = Signer::new(message, signer.clone())
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Base case binary".into(),
                buf.into(),
                Some(Ok("Compatibility concern.".into()))));

        // Base case text.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
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

                let cipher = SymmetricAlgorithm::default();
                let sk = SessionKey::new(cipher.key_size()?);
                let mut buf = Vec::new();
                let message = Message::new(&mut buf);
                let message = Armorer::new(message)
                    .add_header("Comment",
                                format!("Plaintext is {:?}",
                                        String::from_utf8_lossy(MESSAGE)))
                    .add_header("Comment",
                                format!("Encrypted using {}", cipher))
                    .add_header("Comment",
                                format!("Session key: {}", hex::encode(&sk)))
                    .build()?;
                let message = Encryptor::with_session_key(message, cipher, sk)?
                    .add_recipients(vec![&recipient])
                    .build()?;
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
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
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

        // Now, compose them correctly (OPS_bob, OPS_anne, lit,
        // SIG_anne, SIG_bob).
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
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
        for format in vec![
            DataFormat::Binary,
            DataFormat::Text,
            DataFormat::Unicode,
            DataFormat::MIME,
            DataFormat::from(b'l'),
            DataFormat::from(b'1'),
            DataFormat::from(0),
        ] {
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);
            let mut buf = Vec::new();
            let message = Message::new(&mut buf);
            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is {:?}",
                                    String::from_utf8_lossy(MESSAGE)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;
            let mut message = Encryptor::with_session_key(message, cipher, sk)?
                .add_recipients(vec![&recipient])
                .build()?;
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

        Ok(t)
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let mut decrypt = pgp.sop()
            .decrypt()
            .verify_cert(data::certificate("bob.pgp"));
        if i >= EXPECT_TWO_SIGS_AT {
            decrypt = decrypt.verify_cert(&self.annes_cert);
        }
        let (verifications, plaintext) =
            decrypt.key(data::certificate("bob-secret.pgp"))
            .ciphertext(artifact)?;

        if let Some(_v) = verifications.get(0) {
            // XXX check verification
        } else {
            return Err(anyhow::anyhow!("No VERIFICATION emitted"));
        }

        if i >= EXPECT_TWO_SIGS_AT {
            if let Some(_v) = verifications.get(1) {
                // XXX check verification
            } else {
                return Err(anyhow::anyhow!("Only one VERIFICATION emitted"));
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
