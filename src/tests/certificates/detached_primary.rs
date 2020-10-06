use std::time::{Duration, SystemTime};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    crypto::S2K,
    types::{
        Features,
        HashAlgorithm,
        KeyFlags,
        SignatureType,
        SymmetricAlgorithm,
    },
    packet::{
        key,
        signature::{SignatureBuilder, subpacket::*},
    },
    parse::Parse,
    serialize::SerializeInto,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        Test,
        TestMatrix,
    },
};

/// Explores how detached primary keys are handled.
pub struct DetachedPrimary {
}

impl DetachedPrimary {
    pub fn new() -> Result<DetachedPrimary> {
        Ok(DetachedPrimary {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }

    // Returns the Bob certificate modified to have a signing subkey.
    fn cert(&self) -> Result<Data> {
        let half_a_year_ago =
            SystemTime::now() - Duration::new(60 * 60 * 24 * 365 / 2, 0);

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().clone();
        let mut primary_signer =
            primary.parts_as_secret()?.clone().into_keypair()?;
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        // Make a new binding and mark the primary key as only
        // certification capable.
        let userid_binding =
            userid.bind(
                &mut primary_signer, &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(half_a_year_ago)?
                    .set_key_flags(&KeyFlags::empty()
                                   .set_certification())?
                    .set_features(&Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let subkey = cert.keys().subkeys().nth(0).unwrap().key().clone();
        let mut subkey_signer =
            subkey.clone().parts_into_secret()?.into_keypair().unwrap();

        let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .set_signature_creation_time(half_a_year_ago)?
            .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

        use openpgp::Packet;
        use openpgp::serialize::Serialize;
        let mut w =
            armor::Writer::new(Vec::new(), armor::Kind::PublicKey)?;
        Packet::from(primary).serialize(&mut w)?;
        Packet::from(userid).serialize(&mut w)?;
        Packet::from(userid_binding).serialize(&mut w)?;
        Packet::from(subkey.clone()).serialize(&mut w)?;
        Packet::from(subkey.bind(
            &mut primary_signer, &cert,
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(half_a_year_ago)?
                .modify_hashed_area(|mut a| {
                    a.add(Subpacket::new(
                        SubpacketValue::KeyFlags(
                            KeyFlags::empty().set_signing()),
                        true)?)?;
                    Ok(a)
                })?
                // We need to create a primary key binding signature.
                .set_embedded_signature(backsig.clone())?)?)
            .serialize(&mut w)?;
        Ok(w.finalize()?.into())
    }
}

impl Test for DetachedPrimary {
    fn title(&self) -> String {
        "Detached primary key".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>Explores how detached primary keys are handled by the \
          implementations.  There seem to be at least two ways to do \
          that, and neither is in full compliance of the RFC4880.</p> \
          \
          <p>The first way is to encode the detached key using a \
          secret key packet and a stub encrypted secret key part. \
          This method is used by GnuPG.</p> \
          \
          <p>The second way is to simply use a public key packet.</p> \
          \
          <p>The test creates an OpenPGP key with a signing-capable \
          subkey, detaches the primary key, and tries to create a \
          signature with the resulting key structure.  The signature \
          is over the string <code>{}</code>.</p>",
          String::from_utf8(self.message().into()).unwrap())
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for DetachedPrimary {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let half_a_year_ago =
            SystemTime::now() - Duration::new(60 * 60 * 24 * 365 / 2, 0);

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().parts_as_secret()?.clone();
        let mut primary_signer = primary.clone().into_keypair()?;
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        // Make a new binding and mark the primary key as only
        // certification capable.
        let userid_binding =
            userid.bind(
                &mut primary_signer, &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(half_a_year_ago)?
                    .set_key_flags(&KeyFlags::empty()
                                   .set_certification())?
                    .set_features(&Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let subkey = cert.keys().subkeys().nth(0).unwrap().key()
            .parts_as_secret()?.clone();
        let mut subkey_signer = subkey.clone().into_keypair().unwrap();

        fn make_test(test: &str, packets: Vec<openpgp::Packet>,
                     expectation: Option<Expectation>)
                     -> Result<(String, Data, Option<Expectation>)> {
            use openpgp::Packet;
            use openpgp::serialize::Serialize;

            let has_secrets = packets.iter().any(|p| match p {
                Packet::SecretKey(_) | Packet::SecretSubkey(_) => true,
                _ => false,
            });

            let mut buf = Vec::new();
            {
                let mut w =
                    armor::Writer::new(&mut buf,
                                       if has_secrets {
                                           armor::Kind::SecretKey
                                       } else {
                                           armor::Kind::PublicKey
                                       })?;
                openpgp::PacketPile::from(packets).serialize(&mut w)?;
                w.finalize()?;
            }
            Ok((test.into(), buf.into(), expectation))
        }

        let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .set_signature_creation_time(half_a_year_ago)?
            .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

        Ok(vec![
            make_test("SecKey SecSubkey", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty().set_signing()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], Some(Ok("Base case".into())))?,

            make_test("SecKey[0xfe stub] SecSubkey", vec![
                {
                    let stub = S2K::Unknown {
                        tag: 101,
                        parameters:
                            Some(vec![0,    // "hash algo"
                                      0x47, // 'G'
                                      0x4e, // 'N'
                                      0x55, // 'U'
                                      1].into()),
                    };
                    primary.clone()
                        .add_secret(key::SecretKeyMaterial::Encrypted(
                            key::Encrypted::new(stub, 0.into(),
                                                vec![].into()))).0
                        .into()
                },
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty().set_signing()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            make_test("SecKey[0xff stub] SecSubkey", vec![
                {
                    // Some minor trickery to change the S2K usage
                    // field from 0xfe (i.e. SHA1-checksum'ed, what
                    // Sequoia emits) to 0xff (16 bit checksum, what
                    // GnuPG emits for stubs).  Of course, the stub is
                    // not checksum'ed at all.
                    let stub = S2K::Unknown {
                        tag: 101,
                        parameters:
                            Some(vec![0,    // "hash algo"
                                      0x47, // 'G'
                                      0x4e, // 'N'
                                      0x55, // 'U'
                                      1].into()),
                    };
                    let mut buf = openpgp::Packet::from(primary.clone()
                        .add_secret(key::SecretKeyMaterial::Encrypted(
                            key::Encrypted::new(stub, 0.into(),
                                                vec![].into()))).0
                    ).to_vec()?;
                    let o = buf.len() - 8; // Offset of S2K usage field.
                    assert_eq!(buf[o], 0xfe);
                    buf[o] = 0xff;
                    openpgp::Packet::from_bytes(&buf)?
                },
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty().set_signing()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            make_test("PubKey SecSubkey", vec![
                {
                   primary.clone()
                        .take_secret().0
                        .into()
                },
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty().set_signing()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let sig = pgp.sign_detached(artifact, self.message())?;
        pgp.new_context()?
            .verify_detached(&self.cert()?, self.message(), &sig)
    }
}
