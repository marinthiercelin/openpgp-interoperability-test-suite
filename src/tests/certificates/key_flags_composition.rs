use std::io::Write;
use std::time::{Duration, SystemTime};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    types::{
        Features,
        HashAlgorithm,
        KeyFlags,
        SignatureType,
        SymmetricAlgorithm,
    },
    packet::signature::{SignatureBuilder, subpacket::*},
    parse::Parse,
    serialize::stream::*,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        ConsumerTest,
        Expectation,
        TestMatrix,
    },
};

/// Explores how key flags sets are looked up and composed.
pub struct KeyFlagsComposition {
}

impl KeyFlagsComposition {
    pub fn new() -> Result<KeyFlagsComposition> {
        Ok(KeyFlagsComposition {
        })
    }

    fn message(&self) -> &'static [u8] {
        crate::tests::MESSAGE
    }

    fn signature(&self) -> Result<Vec<u8>> {
        // Sign with Bob's subkey.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let signing_keypair =
            cert.keys().nth(1).unwrap()
            .key().clone().parts_into_secret()?.into_keypair()?;

        let mut sig = Vec::new();
        let message = Message::new(&mut sig);
        let message = Armorer::new(message)
            .kind(armor::Kind::Signature)
            .build()?;
        let b = SignatureBuilder::new(SignatureType::Binary);
        let mut signer = Signer::with_template(message, signing_keypair, b)
            .detached()
            .build()?;
        signer.write_all(self.message())?;
        signer.finalize()?;
        Ok(sig)
    }
}

impl crate::plan::Runnable<TestMatrix> for KeyFlagsComposition {
    fn title(&self) -> String {
        "Key Flags Composition".into()
    }

    fn description(&self) -> String {
      format!(
        "<p>Explores how key flags sets are looked up and composed. \
        Key flags are stored in key flags subpackets on subkey binding \
        signatures and direct key signatures.  Furthermore, there \
        could be more than one of such subpackets on a signature. \
        This test explores whether key flags subpackets on direct key \
        signatures are honored, and if multiple subpackets are given, \
        what their precedence relation is, and how they are composed \
        (e.g. is a union or intersection computed, or first or last \
        subpacket wins, etc.), and whether a default value is used if \
        the subpacket is not present (e.g., GnuPG appears to default \
        to CSEA).</p>\
        \
        <p>The notation used in the rows is as follows.  First, a \
        letter identifies a certificate component: <code>p</code> for \
        primary key, <code>u</code> for userid, and <code>s</code> for \
        subkey.  Each component is followed by any number of key flag \
        sets, enclosed in square brackets.  The letters \
        <code>CSEA</code> refer to certification, signing, encryption, \
        and authentication capabilities.  For example, <code>p u[C] \
        s[S]</code> denotes a certificate with the primary key capable \
        of certification, and the sole subkey capable of signing. \
        This is the base case.  A test like <code>p u[C] s[][S]</code> \
        explores how an empty flag set followed by one denoting \
        signing capabilities is handled.</p>\
        \
        <p>The signature is over the string <code>{}</code>.</p>",
        String::from_utf8(self.message().into()).unwrap())
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Signature".into(), self.signature().unwrap().into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for KeyFlagsComposition {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let half_a_year_ago =
            SystemTime::now() - Duration::new(60 * 60 * 24 * 365 / 2, 0);

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().clone();
        let mut primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        // Make a new binding and mark the primary key as only
        // certification capable.
        let userid_binding =
            userid.bind(
                &mut primary_signer, &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(half_a_year_ago)?
                    .set_key_flags(KeyFlags::empty()
                                   .set_certification())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let subkey = cert.keys().subkeys().nth(0).unwrap().key().clone();
        let mut subkey_signer =
            subkey.clone().parts_into_secret()?.into_keypair().unwrap();

        let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

        let make_test = |test, packets: Vec<openpgp::Packet>, expectation| {
            super::make_test(test, packets, expectation)
        };
        Ok(vec![
            make_test("p u[C] s[S]", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
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

            make_test("p u[C] s[E]", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty()
                                        .set_transport_encryption()
                                        .set_storage_encryption()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], Some(Err("Base case, encryption subkey".into())))?,

            make_test("p u[C] s[][S]", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty()),
                                true)?)?;
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

            make_test("p u[C] s[S][]", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty().set_signing()),
                                true)?)?;
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            // Same as above, but with no key flags on the subkey, and
            // key flags in various combinations on the direct key
            // signature.  We add `C` for consistency.
            make_test("p[CS] u[C] s", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()
                                    .set_signing()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], Some(Ok("[S]ubpackets on the direct-key signature apply to the \
                        entire key".into())))?,

            make_test("p[CE] u[C] s", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()
                                    .set_transport_encryption()
                                    .set_storage_encryption()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], Some(Err("Encryption subkey".into())))?,

            make_test("p[C][CS] u[C] s", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()),
                            true)?)?;
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()
                                    .set_signing()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            make_test("p[CS][C] u[C] s", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()
                                    .set_signing()),
                            true)?)?;
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()
                                    .set_certification()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            // Check if key flags are honored at all.
            make_test("p[] u[C] s[]", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,

            // Contradicting sets on direct key signature and subkey
            // binding signature.
            make_test("p[] u[C] s[S]", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
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

            make_test("p[S] u[C] s[]", vec![
                primary.clone().into(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .modify_hashed_area(|mut a| {
                        a.add(Subpacket::new(
                            SubpacketValue::KeyFlags(
                                KeyFlags::empty().set_signing()),
                            true)?)?;
                        Ok(a)
                    })?
                .sign_direct_key(&mut primary_signer, &primary)?.into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .modify_hashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::KeyFlags(
                                    KeyFlags::empty()),
                                true)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(backsig.clone())?)?
                    .into(),
            ], None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(artifact, self.message(), &self.signature()?)
    }
}
