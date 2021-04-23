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
    packet::{
        signature::{SignatureBuilder, subpacket::*},
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
        Test,
        TestMatrix,
    },
};

/// Explores how subpackets on binding signatures are handled.
pub struct BindingSignatureSubpackets {
}

impl BindingSignatureSubpackets {
    pub fn new() -> Result<BindingSignatureSubpackets> {
        Ok(BindingSignatureSubpackets {
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

impl Test for BindingSignatureSubpackets {
    fn title(&self) -> String {
        "Binding signature subpackets".into()
    }

    fn description(&self) -> String {
      format!(
          "<p>Explores how subpackets on binding signatures are
          handled.</p> \
          \
          <p>The test creates variations of OpenPGP certs with a \
          signing-capable subkey, and tries to verify a signature \
          with it.  The certificate has a signing-capable subkey, and \
          the subkey's binding signature (SKB) as well as the embedded \
          primary key binding signature (PKB) are modified.  The \
          signature is over the string <code>{}</code>.</p>",
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

impl ConsumerTest for BindingSignatureSubpackets {
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

        let fake_backsig =
            SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                .set_signature_creation_time(half_a_year_ago)?
                .sign_primary_key_binding(&mut primary_signer,
                                          &primary,
                                          &subkey)?;
        let unknown_subpacket = Subpacket::new(SubpacketValue::Unknown {
            tag: SubpacketTag::Unknown(127),
            body: b"value".to_vec(),
        }, false)?;
        let crit_unknown_subpacket = Subpacket::new(SubpacketValue::Unknown {
            tag: SubpacketTag::Unknown(127),
            body: b"value".to_vec(),
        }, true)?;
        let unknown_notation = Subpacket::new(SubpacketValue::NotationData(
            NotationData::new("unknown@tests.sequoia-pgp.org",
                              b"value", None)
        ), false)?;
        let crit_unknown_notation = Subpacket::new(SubpacketValue::NotationData(
            NotationData::new("unknown@tests.sequoia-pgp.org",
                              b"value", None)
        ), true)?;


        let primary_fp = cert.fingerprint();
        let primary_id = cert.keyid();

        let fictitious_v6_issuer_fp = Subpacket::new(
            SubpacketValue::Unknown {
                tag: SubpacketTag::IssuerFingerprint,
                body: vec![
                    6, // Fictitious version 6 fingerprint
                    // 34 bytes of fictitious fingerprint
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA,
                ],
            },
            false)?;

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
            ], Some(Ok("Base case.".into())))?,

            // Mucking with the subkey binding signature.
            make_test("SKB: Issuer FP only", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::IssuerFingerprint(
                                    primary_fp.clone()),
                                false)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Issuer, V6 issuer FP", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(primary_id.clone()),
                                false)?)?;
                            a.add(fictitious_v6_issuer_fp.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Issuer, fake issuer", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(primary_id.clone()),
                                false)?)?;
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(
                                    "AAAA BBBB CCCC DDDD".parse()?),
                                false)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Fake issuer, issuer", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(
                                    "AAAA BBBB CCCC DDDD".parse()?),
                                false)?)?;
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(primary_id.clone()),
                                false)?)?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Fake issuer", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::Issuer(
                                    "AAAA BBBB CCCC DDDD".parse()?),
                                false)?)?;
                            Ok(a)
                        })?
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

            make_test("SKB: No issuer at all", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                {
                    // We need to add one that we can remove
                    // later.
                    let mut sig = subkey.bind(
                        &mut primary_signer, &cert,
                        SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_signature_creation_time(half_a_year_ago)?
                            .set_key_flags(KeyFlags::empty().set_signing())?
                            .modify_unhashed_area(|mut a| {
                                a.add(Subpacket::new(
                                    SubpacketValue::Issuer(
                                        "AAAA BBBB CCCC DDDD".parse()?),
                                    false)?)?;
                                Ok(a)
                            })?
                            // We need to create a primary key binding
                            // signature.
                            .set_embedded_signature(
                                SignatureBuilder::new(
                                    SignatureType::PrimaryKeyBinding)
                                    .set_signature_creation_time(half_a_year_ago)?
                                    .sign_primary_key_binding(
                                        &mut subkey_signer,
                                        &primary,
                                        &subkey)?)?)?;
                    sig.unhashed_area_mut().remove_all(SubpacketTag::Issuer);
                    assert_eq!(sig.issuers().count(), 0);
                    assert_eq!(sig.issuer_fingerprints().count(), 0);
                    sig.into()
                },
            ], None)?,

            make_test("SKB: Unknown subpacket", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_hashed_area(|mut a| {
                            a.add(unknown_subpacket.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Critical unknown subpacket", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_hashed_area(|mut a| {
                            a.add(crit_unknown_subpacket.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Err("Critical unknown subpacket invalidates signature."
                        .into())))?,

            make_test("SKB: Unknown subpacket, unhashed", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(unknown_subpacket.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Critical unknown subpacket, unhashed", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(crit_unknown_subpacket.clone())?;
                            Ok(a)
                        })?
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

            make_test("SKB: Unknown notation", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_hashed_area(|mut a| {
                            a.add(unknown_notation.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Critical unknown notation", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_hashed_area(|mut a| {
                            a.add(crit_unknown_notation.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Err("Critical unknown notation invalidates signature."
                        .into())))?,

            make_test("SKB: Unknown notation, unhashed", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(unknown_notation.clone())?;
                            Ok(a)
                        })?
                        // We need to create a primary key binding signature.
                        .set_embedded_signature(
                            SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Critical unknown notation, unhashed", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(crit_unknown_notation.clone())?;
                            Ok(a)
                        })?
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

            make_test("SKB: Backsig, fake backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::EmbeddedSignature(
                                  SignatureBuilder::new(
                                    SignatureType::PrimaryKeyBinding)
                                    .set_signature_creation_time(half_a_year_ago)?
                                    .sign_primary_key_binding(&mut subkey_signer,
                                                              &primary,
                                                              &subkey)?),
                                false)?)?;
                            a.add(Subpacket::new(
                                SubpacketValue::EmbeddedSignature(
                                    fake_backsig.clone()),
                                false)?)?;
                            Ok(a)
                        })?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("SKB: Fake backsig, backsig", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        .modify_unhashed_area(|mut a| {
                            a.add(Subpacket::new(
                                SubpacketValue::EmbeddedSignature(
                                    fake_backsig.clone()),
                                false)?)?;
                            a.add(Subpacket::new(
                                SubpacketValue::EmbeddedSignature(
                                  SignatureBuilder::new(
                                    SignatureType::PrimaryKeyBinding)
                                    .set_signature_creation_time(half_a_year_ago)?
                                    .sign_primary_key_binding(&mut subkey_signer,
                                                              &primary,
                                                              &subkey)?),
                                false)?)?;
                            Ok(a)
                        })?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            // Diddling with the primary key binding signature.
            make_test("PKB: Issuer FP only", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::IssuerFingerprint(
                                            primary_fp.clone()),
                                        false)?)?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Issuer, V6 issuer FP", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(primary_id.clone()),
                                        false)?)?;
                                    a.add(fictitious_v6_issuer_fp.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Issuer, fake issuer", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(primary_id.clone()),
                                        false)?)?;
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(
                                            "AAAA BBBB CCCC DDDD".parse()?),
                                        false)?)?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Fake issuer, issuer", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(
                                            "AAAA BBBB CCCC DDDD".parse()?),
                                        false)?)?;
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(primary_id.clone()),
                                        false)?)?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Fake issuer", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(
                                            "AAAA BBBB CCCC DDDD".parse()?),
                                        false)?)?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

            make_test("PKB: No issuer at all", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid_binding.clone().into(),
                subkey.clone().into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_signature_creation_time(half_a_year_ago)?
                        .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding
                        // signature.
                        .set_embedded_signature({
                            // We need to add one that we can remove
                            // later.
                            let mut sig = SignatureBuilder::new(
                                SignatureType::PrimaryKeyBinding)
                                .set_signature_creation_time(half_a_year_ago)?
                                .modify_unhashed_area(|mut a| {
                                    a.add(Subpacket::new(
                                        SubpacketValue::Issuer(
                                            "AAAA BBBB CCCC DDDD".parse()?),
                                        false)?)?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(
                                    &mut subkey_signer,
                                    &primary,
                                    &subkey)?;
                            sig.unhashed_area_mut().remove_all(SubpacketTag::Issuer);
                            assert_eq!(sig.issuers().count(), 0);
                            assert_eq!(sig.issuer_fingerprints().count(), 0);
                            sig
                        })?)?
                .into()
            ], None)?,

            make_test("PKB: Unknown subpacket", vec![
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
                                .modify_hashed_area(|mut a| {
                                    a.add(unknown_subpacket.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Critical unknown subpacket", vec![
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
                                .modify_hashed_area(|mut a| {
                                    a.add(crit_unknown_subpacket.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Err("Critical unknown subpacket invalidates signature."
                        .into())))?,

            make_test("PKB: Unknown subpacket, unhashed", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(unknown_subpacket.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Critical unknown subpacket, unhashed", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(crit_unknown_subpacket.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

            make_test("PKB: Unknown notation", vec![
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
                                .modify_hashed_area(|mut a| {
                                    a.add(unknown_notation.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Critical unknown notation", vec![
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
                                .modify_hashed_area(|mut a| {
                                    a.add(crit_unknown_notation.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Err("Critical unknown notation invalidates signature."
                        .into())))?,

            make_test("PKB: Unknown notation, unhashed", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(unknown_notation.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], Some(Ok("Interoperability concern.".into())))?,

            make_test("PKB: Critical unknown notation, unhashed", vec![
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
                                .modify_unhashed_area(|mut a| {
                                    a.add(crit_unknown_notation.clone())?;
                                    Ok(a)
                                })?
                                .sign_primary_key_binding(&mut subkey_signer,
                                                          &primary,
                                                          &subkey)?)?)?
                    .into(),
            ], None)?,

        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(artifact, self.message(), &self.signature()?)
    }
}
