use std::borrow::Borrow;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::{
    Features,
    KeyFlags,
    SignatureType,
    SymmetricAlgorithm,
};
use openpgp::packet::key;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::Parse;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    plan::TestPlan,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

mod revoked_key;
mod primary_key_binding;
mod key_flags_composition;
mod perturbed_certs;
mod expiration;
mod detached_primary;
mod binding_signature_subpackets;
mod im_my_own_grandpa;
mod temporary_validity;
mod mock_mceliece;

fn make_test<I, P>(test: &str, packets: I,
             expectation: Option<Expectation>)
             -> Result<(String, Data, Option<Expectation>)>
    where I: IntoIterator<Item = P>,
          P: Borrow<openpgp::Packet>,
{
    use openpgp::Packet;
    use openpgp::serialize::Serialize;

    let packets = packets.into_iter().collect::<Vec<_>>();
    let has_secrets = packets.iter().any(|p| match p.borrow() {
        Packet::SecretKey(_) | Packet::SecretSubkey(_) => true,
        _ => false,
    });

    let mut buf = Vec::new();
    {
        use openpgp::armor;
        let mut w =
            armor::Writer::new(&mut buf,
                               if has_secrets {
                                   armor::Kind::SecretKey
                               } else {
                                   armor::Kind::PublicKey
                               })?;
        for p in packets {
            p.borrow().serialize(&mut w)?;
        }
        w.finalize()?;
    }
    Ok((test.into(), buf.into(), expectation))
}

/// Tests how implementation interpret encryption keyflags.
struct EncryptionKeyFlags {
    cert: openpgp::Cert,
    aesk: openpgp::packet::Key<key::PublicParts, key::SubordinateRole>,
    keyid_a: openpgp::KeyID,
    keyid_b: openpgp::KeyID,
}

impl EncryptionKeyFlags {
    pub fn new() -> Result<EncryptionKeyFlags> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let keyid_a = cert.keys().subkeys().nth(0).unwrap().key().keyid();
        let aesk: openpgp::packet::Key<key::PublicParts, key::SubordinateRole> =
            openpgp::packet::key::Key4::generate_rsa(2048)?
                .parts_into_public().into();
        let keyid_b = aesk.keyid();
        Ok(EncryptionKeyFlags {
            cert, aesk, keyid_a, keyid_b,
        })
    }
}

impl Test for EncryptionKeyFlags {
    fn title(&self) -> String {
        "Interpretation of encryption keyflags".into()
    }

    fn description(&self) -> String {
        format!(
            "OpenPGP has two kinds of key usage flags that cover encryption: \
             \
             0x04 - This key may be used to encrypt communications. \
             0x08 - This key may be used to encrypt storage. \
             \
             This tests how implementation interpret these flags.\
             \
             This test uses two encryption subkeys, A ({}) and B ({}).",
            self.keyid_a, self.keyid_b)
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for EncryptionKeyFlags {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let mut primary_signer =
            self.cert.primary_key()
            .key().clone().parts_into_secret()?.into_keypair()?;
        let uid =
            self.cert.userids().with_policy(super::P, None).nth(0).unwrap();
        let cert_stem: Vec<openpgp::Packet> = vec![
            self.cert.primary_key().key().clone().into(),
            uid.userid().clone().into(),
            uid.binding_signature().clone().into(),
        ];
        let key_a = self.cert.keys().subkeys().nth(0).unwrap().key();
        let key_b = &self.aesk;

        Ok(vec![
            make_test("A 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("A 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_storage_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("A 0x0c, B 0x0c", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption()
                                        .set_storage_encryption())?)?
                     .into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption()
                                        .set_storage_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("B 0x0c, A 0x0c", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption()
                                        .set_storage_encryption())?)?
                     .into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption()
                                        .set_storage_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("A 0x04, B 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption())?)?
                     .into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_storage_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("A 0x08, B 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_storage_encryption())?)?
                     .into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("B 0x04, A 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption())?)?
                     .into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_storage_encryption())?)?
                     .into());
                 p
            }, None)?,
            make_test("B 0x08, A 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_storage_encryption())?)?
                     .into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     SignatureBuilder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(KeyFlags::empty()
                                        .set_transport_encryption())?)?
                     .into());
                 p
             }, None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let pp = openpgp::PacketPile::from_bytes(
            &pgp.encrypt(artifact, b"Hello World!")?
        )?;

        let mut encrypted_to = Vec::new();
        for p in pp.children() {
            match p {
                openpgp::Packet::PKESK(pkesk) => {
                    let r = pkesk.recipient();
                    if r == &self.keyid_a {
                        encrypted_to.push("A");
                    } else if r == &self.keyid_b {
                        encrypted_to.push("B");
                    } else {
                        encrypted_to.push("unknown key");
                    }
                },
                openpgp::Packet::SKESK(_) => encrypted_to.push("password"),
                _ => (),
            }
        }

        Ok(format!("Encrypted to {}", encrypted_to.join(", "))
           .into_bytes().into())
    }
}

/// Tests how implementation interpret encryption keyflags.
struct PrimaryKeyFlags {
}

impl PrimaryKeyFlags {
    pub fn new() -> Result<PrimaryKeyFlags> {
        Ok(PrimaryKeyFlags {
        })
    }
}

impl Test for PrimaryKeyFlags {
    fn title(&self) -> String {
        "Interpretation of primary key flags".into()
    }

    fn description(&self) -> String {
        "<p>This tests various ways of specifying the primary key's \
         flags.  Key flags can be provided using direct key signatures, \
         as well as binding signatures on userids.</p> \
         <p>Notation: p[flags-on-direct-key-sig] u[flags-on-uid-binding] \
         s[flags-on-binding], where CSEA refer to certification, signing, \
         encryption, and authentication capabilities, and 0 refers to an \
         explicit empty set (the subpacket is present, but empty).  \
         The key is then used to do an encrypt-decrypt roundtrip.</p>"
            .into()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PrimaryKeyFlags {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary_key().key().clone().parts_into_secret()?;
        let primary_packet = openpgp::Packet::from(primary.clone());
        let mut primary_signer = primary.clone().into_keypair()?;
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        let subkey = cert.keys().subkeys().nth(0).unwrap().key().clone();

        Ok(vec![
            make_test("p uC sE (basecase)", vec![
                primary_packet.clone(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_key_flags(KeyFlags::empty()
                                       .set_certification())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("pC uC sE", vec![
                primary_packet.clone(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .set_key_flags(KeyFlags::empty()
                                   .set_certification())?
                .set_features(Features::empty().set_mdc())?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_direct_key(&mut primary_signer, None)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_key_flags(KeyFlags::empty()
                                       .set_certification())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("pC u sE", vec![
                primary_packet.clone(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .set_key_flags(KeyFlags::empty()
                                   .set_certification())?
                .set_features(Features::empty().set_mdc())?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_direct_key(&mut primary_signer, None)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification))?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("pC uS sE", vec![
                primary_packet.clone(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .set_key_flags(KeyFlags::empty()
                                   .set_certification())?
                .set_features(Features::empty().set_mdc())?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_direct_key(&mut primary_signer, None)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_key_flags(KeyFlags::empty()
                                       .set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("pC u0 sE", vec![
                primary_packet.clone(),
                SignatureBuilder::new(SignatureType::DirectKey)
                    .set_key_flags(KeyFlags::empty()
                                   .set_certification())?
                .set_features(Features::empty().set_mdc())?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_direct_key(&mut primary_signer, None)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_key_flags(KeyFlags::empty())?)?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("p uS sE", vec![
                primary_packet.clone(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_key_flags(KeyFlags::empty()
                                       .set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("p u sE", vec![
                primary_packet.clone(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification))?
                    .into(),
                subkey.clone().parts_into_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())?)?
                    .into(),
            ], None)?,

            make_test("p u", vec![
                primary_packet.clone(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification))?
                    .into(),
            ], None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(&super::extract_cert(artifact)?, b"Hello World!")?;
        pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Certificates");
    plan.add(Box::new(EncryptionKeyFlags::new()?));
    plan.add(Box::new(PrimaryKeyFlags::new()?));
    plan.add(Box::new(primary_key_binding::PrimaryKeyBinding::new()?));
    plan.add(Box::new(key_flags_composition::KeyFlagsComposition::new()?));
    plan.add(Box::new(perturbed_certs::PerturbedCerts::new()?));
    plan.add(Box::new(expiration::CertExpiration::new()?));
    plan.add(Box::new(detached_primary::DetachedPrimary::new()?));
    plan.add(Box::new(
        binding_signature_subpackets::BindingSignatureSubpackets::new()?));
    plan.add(Box::new(im_my_own_grandpa::ImMyOwnGrandpa::new()?));
    plan.add(Box::new(temporary_validity::TemporaryValidity::new()?));
    plan.add(Box::new(mock_mceliece::MockMcEliece::new()?));

    revoked_key::schedule(plan)?;
    Ok(())
}
