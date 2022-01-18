use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::SessionKey,
    fmt::hex,
    packet::prelude::*,
    parse::Parse,
    serialize::{Serialize, stream::*},
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
        "This is a collection of messages that are malformed, i.e. \
         they do not conform to the OpenPGP Message grammar."
            .into()
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
        // Pop the encryptor.
        let message = message.finalize_one()?.unwrap();
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
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
        let message = Encryptor::with_session_key(message, cipher, sk)?
            .add_recipients(vec![&recipient])
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Two messages, nested".into(),
                buf.into(),
                Some(Err("Malformed message.".into()))));

        // Two literal packets.
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
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;
        t.push(("Two literal packets".into(),
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
                                String::from_utf8_lossy(MESSAGE)))
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
                                String::from_utf8_lossy(MESSAGE)))
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
