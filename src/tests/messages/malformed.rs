use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::SessionKey,
    fmt::hex,
    packet::prelude::*,
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
        MESSAGE,
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

const MESSAGE_0: &[u8] = b"First";
const MESSAGE_1: &[u8] = b"Second";

/// Tests support for malformed messages.
pub struct Malformed {
}

impl Malformed {
    pub fn new() -> Result<Malformed> {
        Ok(Malformed {
        })
    }
}

impl Test for Malformed {
    fn title(&self) -> String {
        "Malformed messages".into()
    }

    fn description(&self) -> String {
        format!(
            "This is a collection of messages that are malformed, i.e. \
             they do not conform to the OpenPGP Message grammar. \
             When a single Literal Data packet is used in a test vector, \
             the usual plaintext {:?} is used, but when two Literal \
             Data Packets are present, {:?} and {:?} is used so that \
             we can tell which packet is picked up by implementations.",
            String::from_utf8_lossy(crate::tests::MESSAGE),
            String::from_utf8_lossy(MESSAGE_0),
            String::from_utf8_lossy(MESSAGE_1))
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Key".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for Malformed {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let mut t = Vec::new();

        // Use the RSA key to increase compatibility.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let recipient =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .nth(0).unwrap().key().clone();

        let cert_ricarda =
            openpgp::Cert::from_bytes(data::certificate("ricarda.pgp"))?;
        let recipient_ricarda =
            cert_ricarda.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption()
            .nth(0).unwrap().key().clone();

        // Base case.
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
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Base case".into(),
                buf.into(),
                Some(Ok("Compatibility concern.".into()))));

        // Two messages, concatenated.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        // Pop the encryptor.
        let message = message.finalize_one()?.unwrap();
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two messages, concatenated".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two nested messages.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two messages, nested".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two nested messages, take two.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        // Pop the encryptor.
        let message = message.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two messages, nested, take two".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two nested messages, take three.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        // Pop the encryptor.
        let message = message.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two messages, nested, take three".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two literal packets.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two literal packets".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two literal packets, first one odd format
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message)
            .format('l'.into())
            .build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Literal/l + Literal/b".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        for &n in &[1, 2, 4, 8, 16, 32] {
            // Two literal packets, first one compressed n-times.
            let cipher = SymmetricAlgorithm::default();
            let sk = SessionKey::new(cipher.key_size()?);
            let mut buf = Vec::new();
            let message = Message::new(&mut buf);
            let message = Armorer::new(message)
                .add_header("Comment",
                            format!("Plaintext is either {:?}",
                                    String::from_utf8_lossy(MESSAGE_0)))
                .add_header("Comment",
                            format!("or {:?}",
                                    String::from_utf8_lossy(MESSAGE_1)))
                .add_header("Comment",
                            format!("Encrypted using {}", cipher))
                .add_header("Comment",
                            format!("Session key: {}", hex::encode(&sk)))
                .build()?;
            let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
                .add_recipients(vec![&recipient])
                .build()?;
            for _ in 0..n {
                message = Compressor::new(message).build()?;
            }
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(MESSAGE_0)?;
            // Pop the literal writer and all compressors.
            for _ in 0..=n {
                message = message.finalize_one()?.unwrap();
            }
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(MESSAGE_1)?;
            message.finalize()?;
            t.push((format!("Two literals, 1st compressed {} times", n),
                    buf.into(),
                    Some(Err("Malformed message.".into()))));
        }

        // Two literal packets, first one null-compressed.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        message = Compressor::new(message)
            .algo(CompressionAlgorithm::Uncompressed).build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_0)?;
        // Pop the literal writer the null-compressor.
        message = message.finalize_one()?.unwrap();
        message = message.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Two literals, 1st null-compressed".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two PKESKs, Two SEIPDv1s.
        let cipher = SymmetricAlgorithm::default();
        let sk_0 = SessionKey::new(cipher.key_size()?);
        let sk_1 = SessionKey::new(cipher.key_size()?);

        let mut buf0 = Vec::new();
        let message0 = Message::new(&mut buf0);
        let message0 =
            Encryptor::with_session_key(message0, cipher, sk_0.clone())?
            .add_recipients(vec![&recipient_ricarda])
            .build()?;
        let mut message0 = LiteralWriter::new(message0).build()?;
        message0.write_all(MESSAGE_0)?;
        message0.finalize()?;

        let mut buf1 = Vec::new();
        let message1 = Message::new(&mut buf1);
        let message1 =
            Encryptor::with_session_key(message1, cipher, sk_1.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message1 = LiteralWriter::new(message1).build()?;
        message1.write_all(MESSAGE_1)?;
        message1.finalize()?;

        use openpgp::PacketPile;
        let pp0 =
            PacketPile::from_bytes(&buf0)?.into_children().collect::<Vec<_>>();
        let pp1 =
            PacketPile::from_bytes(&buf1)?.into_children().collect::<Vec<_>>();

        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let mut message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key is either: {}", hex::encode(&sk_0)))
            .add_header("Comment",
                        format!("or: {}", hex::encode(&sk_1)))
            .build()?;

        pp0[0].serialize(&mut message)?;
        pp1[0].serialize(&mut message)?;
        pp0[1].serialize(&mut message)?;
        pp1[1].serialize(&mut message)?;
        message.finalize()?;

        t.push(("Two PKESKs, two SEIPDv1s".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // No literal packet.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let message =
            Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        message.finalize()?;
        t.push(("No plaintext".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // No literal packet.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message =
            Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Bare plaintext".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // OPS + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut ops = OnePassSig3::new(SignatureType::Binary);
        ops.set_pk_algo(cert.primary_key().pk_algo());
        ops.set_hash_algo(Default::default());
        ops.set_issuer(cert.primary_key().keyid());
        Packet::from(ops).serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("OPS + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Signature + Literal.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let signing_keypair =
            cert.primary_key().key().clone().parts_into_secret()?
            .into_keypair()?;
        let mut signer = Signer::new(message, signing_keypair)
            .detached()
            .build()?;
        signer.write_all(b"Make it so, number one!")?;
        // Pop the signer.
        let message = signer.finalize_one()?.unwrap();
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Signature + Literal".into(),
                buf.into(),
                Some(Ok("Old-style signed message.".into()))));

        // Literal + Signature.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let message = message.finalize_one()?.unwrap();
        let signing_keypair =
            cert.primary_key().key().clone().parts_into_secret()?
            .into_keypair()?;
        let mut signer = Signer::new(message, signing_keypair)
            .detached()
            .build()?;
        signer.write_all(b"Make it so, number one!")?;
        signer.finalize()?;
        t.push(("Literal + Signature".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // PKESK + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        Packet::from(PKESK3::for_recipient(cipher, &sk, &recipient)?)
            .serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("PKESK + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal + PKESK.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        Packet::from(PKESK3::for_recipient(cipher, &sk, &recipient)?)
            .serialize(&mut message)?;
        message.finalize()?;
        t.push(("Literal + PKESK".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Key + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        Packet::from(cert.primary_key().key().clone())
            .serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Key + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal + Key.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        Packet::from(cert.primary_key().key().clone())
            .serialize(&mut message)?;
        message.finalize()?;
        t.push(("Literal + Key".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Unknown + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut unknown = Unknown::new(
            Tag::Unknown(0x63), anyhow::anyhow!("Unknown packet"));
        unknown.set_body(MESSAGE.into());
        Packet::from(unknown).serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Unknown packet + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal + Unknown.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        let mut unknown = Unknown::new(
            Tag::Unknown(0x63), anyhow::anyhow!("Unknown packet"));
        unknown.set_body(MESSAGE.into());
        Packet::from(unknown).serialize(&mut message)?;
        message.finalize()?;
        t.push(("Literal + unknown packet".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // MDC + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mdc = MDC::from([0; 20]);
        Packet::from(mdc).serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("MDC packet + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // MDC||Literal + Literal.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        // Construct a short MDC packet.
        let mut first = Literal::new(DataFormat::Binary);
        first.set_body(MESSAGE_0.into());
        let first = Packet::from(first).to_vec()?;
        message.write_all(&[0xd3, (20 - first.len()) as u8])?;
        for _ in 0..20 - first.len() {
            message.write_all(&[0])?;
        }
        message.write_all(&first)?;
        // Now the second Literal.
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("MDC||Literal + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // MDC(Literal) + Literal.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        // Construct a long MDC packet.
        let mut first = Literal::new(DataFormat::Binary);
        first.set_body(MESSAGE_0.into());
        let first = Packet::from(first).to_vec()?;
        message.write_all(&[
            0xd3,
            (20 + first.len()) as u8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])?;
        message.write_all(&first)?;
        // Now the second Literal.
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("MDC(Literal) + Literal".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal + MDC.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        let mdc = MDC::from([0; 20]);
        Packet::from(mdc).serialize(&mut message)?;
        message.finalize()?;
        t.push(("Literal + MDC packet".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Marker + Literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        Packet::Marker(Default::default()).serialize(&mut message)?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Marker + Literal".into(),
                buf.into(),
                Some(Ok("Marker packets must be ignored.".into()))));

        // Marker(Literal) + Literal.
        let cipher = SymmetricAlgorithm::default();
        let sk = SessionKey::new(cipher.key_size()?);
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message)
            .add_header("Comment",
                        format!("Plaintext is either {:?}",
                                String::from_utf8_lossy(MESSAGE_0)))
            .add_header("Comment",
                        format!("or {:?}",
                                String::from_utf8_lossy(MESSAGE_1)))
            .add_header("Comment",
                        format!("Encrypted using {}", cipher))
            .add_header("Comment",
                        format!("Session key: {}", hex::encode(&sk)))
            .build()?;
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        // Construct a long Marker packet.
        let mut first = Literal::new(DataFormat::Binary);
        first.set_body(MESSAGE_0.into());
        let first = Packet::from(first).to_vec()?;
        message.write_all(&[
            0xca,
            (3 + first.len()) as u8,
            'P' as u8, 'G' as u8, 'P' as u8,
        ])?;
        message.write_all(&first)?;
        // Now the second Literal.
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE_1)?;
        message.finalize()?;
        t.push(("Marker(Literal) + Literal".into(),
                buf.into(),
                None));


        for &n in &[0, 15, 16, 23] {
            use openpgp::packet::header::*;
            use openpgp::serialize::Marshal;

            // Reserved(n) + Literal.
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
            let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
                .add_recipients(vec![&recipient])
                .build()?;
            // Construct a weird packet.
            let body = &[0, 1, 2];
            let header = Header::new(
                CTB::new(Tag::Unknown(n)),
                BodyLength::Full(body.len() as u32));
            header.serialize(&mut message)?;
            message.write_all(body)?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(MESSAGE)?;
            message.finalize()?;
            t.push((format!("Reserved({}) + Literal", n),
                    buf.into(),
                    Some(Err("Malformed message.".into()))));
        }

        // Literal + Byte.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        message.write_all(b"A")?;
        message.finalize()?;
        t.push(("Literal + byte".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal + Bytes.
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
        let message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        // Pop the literal writer.
        let mut message = message.finalize_one()?.unwrap();
        message.write_all(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
        message.finalize()?;
        t.push(("Literal + bytes".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal packet eating the MDC packet.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        // 00000000  cb                                                 CTB
        // 00000001     14                                              length
        // 00000002        62                                           format
        // 00000003           00                                        filename_len
        // 00000004              00 00 00 00                            date
        // 00000008                           48 65 6c 6c 6f 20 57 6f           Hello Wo
        // 00000010  72 6c 64 20 3a 29                                  rld :)
        message.write_all(&[
            0xcb, // CTB
            0x14 + 22, // Length
            DataFormat::Binary.into(), // Format
            0, // Filename length
            0, 0, 0, 0, // Timestamp
        ])?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Literal eating MDC".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal packet's filename swallowing the literal.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        message.write_all(&[
            0xcb, // CTB
            0x14, // Length
            DataFormat::Binary.into(), // Format
            4 /* Timestamp */ + MESSAGE.len() as u8, // Filename length
            0, 0, 0, 0, // Timestamp
        ])?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Filename eating literal packet".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Literal packet's filename eating MDC.
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
        let mut message = Encryptor::with_session_key(message, cipher, sk.clone())?
            .add_recipients(vec![&recipient])
            .build()?;
        message.write_all(&[
            0xcb, // CTB
            0x14, // Length
            DataFormat::Binary.into(), // Format
            4 /* Timestamp */ + MESSAGE.len() as u8 + 22 /* MDC */, // Filename length
            0, 0, 0, 0, // Timestamp
        ])?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Filename eating MDC".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));


        Ok(t)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.sop()
            .decrypt()
            .key(data::certificate("bob-secret.pgp"))
            .ciphertext(artifact)
            .map(|(_verifications, plaintext)| plaintext)
    }
}
