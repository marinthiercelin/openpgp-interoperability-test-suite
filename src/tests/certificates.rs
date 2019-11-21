use sequoia_openpgp as openpgp;
use openpgp::types::{
    Features,
    KeyFlags,
    SignatureType,
    SymmetricAlgorithm,
};
use openpgp::packet::key;
use openpgp::packet::signature::Builder;
use openpgp::parse::Parse;

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

fn make_test(test: &str, packets: Vec<openpgp::Packet>)
             -> Result<(String, Data)> {
    use openpgp::Packet;
    use openpgp::serialize::Serialize;

    let has_secrets = packets.iter().any(|p| match p {
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
                               },
                               &[])?;
        openpgp::PacketPile::from(packets).serialize(&mut w)?;
        w.finalize()?;
    }
    Ok((test.into(), buf.into()))
}

/// Tests how implementation interpret encryption keyflags.
struct EncryptionKeyFlags {
    cert: openpgp::TPK,
    aesk: openpgp::packet::Key<key::PublicParts, key::SubordinateRole>,
    keyid_a: openpgp::KeyID,
    keyid_b: openpgp::KeyID,
}

impl EncryptionKeyFlags {
    pub fn new() -> Result<EncryptionKeyFlags> {
        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?;
        let keyid_a = cert.subkeys().nth(0).unwrap().key().keyid();
        let aesk: openpgp::packet::Key<key::PublicParts, key::SubordinateRole> =
            openpgp::packet::key::Key4::generate_rsa(2048)?
                .mark_parts_public().into();
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

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for EncryptionKeyFlags {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        let mut primary_signer =
            self.cert.primary().clone().mark_parts_secret()?.into_keypair()?;
        let cert_stem: Vec<openpgp::Packet> = vec![
            self.cert.primary().clone().into(),
            self.cert.userids().nth(0).unwrap().userid().clone().into(),
            self.cert.userids().nth(0).unwrap().binding_signature(None).unwrap()
                .clone().into(),
        ];
        let key_a = self.cert.subkeys().nth(0).unwrap().key();
        let key_b = &self.aesk;

        Ok(vec![
            make_test("A 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None)?.into());
                 p
            })?,
            make_test("A 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p
            })?,
            make_test("A 0x0c, B 0x0c", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p
            })?,
            make_test("B 0x0c, A 0x0c", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p
            })?,
            make_test("A 0x04, B 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p
            })?,
            make_test("A 0x08, B 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None)?.into());
                 p
            })?,
            make_test("B 0x04, A 0x08", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p
            })?,
            make_test("B 0x08, A 0x04", {
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None)?.into());
                 p
             })?,
        ])
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
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
           .into_bytes().into_boxed_slice())
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
        "This tests various ways of specifying the primary key's \
         flags.  Key flags can be provided using direct key signatures, \
         as well as binding signatures on userids.  \
         Notation: p[flags-on-direct-key-sig] u[flags-on-uid-binding] \
         s[flags-on-binding], where CSEA refer to certification, signing, \
         encryption, and authentication capabilities, and 0 refers to an \
         explicit empty set (the subpacket is present, but empty).  \
         The key is then used to do an encrypt-decrypt roundtrip."
            .into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PrimaryKeyFlags {
    fn produce(&self) -> Result<Vec<(String, Data)>> {
        let cert =
            openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary = cert.primary().clone().mark_parts_secret()?;
        let mut primary_signer = primary.clone().into_keypair()?;
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        let subkey = cert.subkeys().nth(0).unwrap().key().clone();

        Ok(vec![
            make_test("p uC sE (basecase)", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate)
                        .set_key_flags(&KeyFlags::default()
                                       .set_certify(true))?
                    .set_features(&Features::default().set_mdc(true))?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?,
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("pC uC sE", vec![
                primary.clone().into(),
                Builder::new(SignatureType::DirectKey)
                    .set_key_flags(&KeyFlags::default()
                                   .set_certify(true))?
                .set_features(&Features::default().set_mdc(true))?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_primary_key_binding(&mut primary_signer)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate)
                        .set_key_flags(&KeyFlags::default()
                                       .set_certify(true))?
                    .set_features(&Features::default().set_mdc(true))?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?,
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("pC u sE", vec![
                primary.clone().into(),
                Builder::new(SignatureType::DirectKey)
                    .set_key_flags(&KeyFlags::default()
                                   .set_certify(true))?
                .set_features(&Features::default().set_mdc(true))?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_primary_key_binding(&mut primary_signer)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate),
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("pC uS sE", vec![
                primary.clone().into(),
                Builder::new(SignatureType::DirectKey)
                    .set_key_flags(&KeyFlags::default()
                                   .set_certify(true))?
                .set_features(&Features::default().set_mdc(true))?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_primary_key_binding(&mut primary_signer)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate)
                        .set_key_flags(&KeyFlags::default()
                                       .set_sign(true))?
                    .set_features(&Features::default().set_mdc(true))?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?,
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("pC u0 sE", vec![
                primary.clone().into(),
                Builder::new(SignatureType::DirectKey)
                    .set_key_flags(&KeyFlags::default()
                                   .set_certify(true))?
                .set_features(&Features::default().set_mdc(true))?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::AES256])?
                .sign_primary_key_binding(&mut primary_signer)?
                .into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate)
                        .set_key_flags(&KeyFlags::default())?,
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("p uS sE", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate)
                        .set_key_flags(&KeyFlags::default()
                                       .set_sign(true))?
                    .set_features(&Features::default().set_mdc(true))?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?,
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("p u sE", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate),
                    None)?.into(),
                subkey.clone().mark_parts_secret()?.into(),
                subkey.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(&KeyFlags::default()
                                       .set_encrypt_for_transport(true)
                                       .set_encrypt_at_rest(true))?,
                    None)?.into(),
            ])?,

            make_test("p u", vec![
                primary.clone().into(),
                userid.clone().into(),
                userid.bind(
                    &mut primary_signer, &cert,
                    Builder::new(SignatureType::PositiveCertificate),
                    None)?.into(),
            ])?,
        ])
    }

    fn consume(&self, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(&super::extract_cert(artifact)?, b"Hello World!")?;
        pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
    }
}

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Certificates");
    report.add(Box::new(EncryptionKeyFlags::new()?));
    report.add(Box::new(PrimaryKeyFlags::new()?));
    Ok(())
}
