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
    packet::signature::{
        SignatureBuilder,
        subpacket::{
            Subpacket,
            SubpacketValue,
        },
    },
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

/// Tests whether implementations pay attention to primary key binding
/// signatures.
pub struct PrimaryKeyBinding {
}

impl PrimaryKeyBinding {
    pub fn new() -> Result<PrimaryKeyBinding> {
        Ok(PrimaryKeyBinding {
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

impl crate::plan::Runnable<TestMatrix> for PrimaryKeyBinding {
    fn title(&self) -> String {
        "Primary key binding signatures".into()
    }

    fn description(&self) -> String {
        format!(
            "<p>A subkey binding signature indicating signing \
             capabilities must carry an embedded primary key signature \
             from the subkey over the primary key.  This tests whether \
             implementations pay attention to that signature.</p>\
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

impl ConsumerTest for PrimaryKeyBinding {
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

        let make_test = |test, packets: Vec<openpgp::Packet>, expectation| {
            super::make_test(test, packets, expectation)
        };
        Ok(vec![
            make_test("Base case", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Base case".into())))?,

            make_test("Hashed backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                {
                    let backsig = SignatureBuilder::new(
                        SignatureType::PrimaryKeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .sign_primary_key_binding(&mut subkey_signer,
                                                  &primary,
                                                  &subkey)?;
                    subkey.bind(
                        &mut primary_signer, &cert,
                        SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_signature_creation_time(half_a_year_ago)?
                            .set_key_flags(KeyFlags::empty().set_signing())?
                            // We need to create a primary key binding signature.
                            .modify_hashed_area(|mut a| {
                                a.add(Subpacket::new(
                                    SubpacketValue::EmbeddedSignature(backsig),
                                    true)?)?;
                                Ok(a)
                            })?)?
                        .into()
                },
            ], Some(Ok("Embedded signature may be hashed".into())))?,

            make_test("No backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    // No backsig
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?)?
                    .into(),
            ], Some(Err("Missing primary key binding signature".into())))?,

            make_test("MD5 backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .set_hash_algo(HashAlgorithm::MD5)
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

            make_test("SHA1 backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .set_hash_algo(HashAlgorithm::SHA1)
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

            make_test("Old backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

            make_test("Expired backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .set_signature_validity_period(
                                    Duration::new(60 * 60 * 24 * 365 / 4, 0))?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Err("Expired primary key binding signature".into())))?,

            make_test("Fake backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                {
                    let fake_backsig = SignatureBuilder::new(
                        SignatureType::PrimaryKeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .sign_primary_key_binding(&mut primary_signer,
                                                  &primary,
                                                  &subkey)?;
                    subkey.bind(
                        &mut primary_signer, &cert,
                        SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_signature_creation_time(half_a_year_ago)?
                            .set_key_flags(KeyFlags::empty().set_signing())?
                            // We need to create a primary key binding signature.
                            .set_embedded_signature(fake_backsig)?)?
                        .into()
                },
            ], Some(Err("Signed using the primary key".into())))?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(artifact, self.message(), &self.signature()?)
    }
}
