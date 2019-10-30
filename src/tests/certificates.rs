use sequoia_openpgp as openpgp;
use openpgp::constants::{SignatureType, KeyFlags};
use openpgp::packet::key;
use openpgp::packet::signature::Builder;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

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
            openpgp::packet::key::Key4::generate_rsa(2048)?.into();
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
            self.cert.primary().clone().mark_parts_secret().into_keypair()?;
        let cert_stem: Vec<openpgp::Packet> = vec![
            self.cert.primary().clone().into(),
            self.cert.userids().nth(0).unwrap().userid().clone().into(),
            self.cert.userids().nth(0).unwrap().binding_signature(None).unwrap()
                .clone().into(),
        ];
        let key_a = self.cert.subkeys().nth(0).unwrap().key();
        let key_b = &self.aesk;

        Ok(vec![
            ("A 0x04".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("A 0x04".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("A 0x0c, B 0x0c".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("B 0x0c, A 0x0c".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true)
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("A 0x04, B 0x08".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None, None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("A 0x08, B 0x04".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("B 0x04, A 0x08".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None, None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
            ("B 0x08, A 0x04".into(),
             openpgp::PacketPile::from({
                 let mut p = cert_stem.clone();
                 p.push(key_b.clone().into());
                 p.push(key_b.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_at_rest(true))?,
                     None, None)?.into());
                 p.push(key_a.clone().into());
                 p.push(key_a.bind(
                     &mut primary_signer,
                     &self.cert,
                     Builder::new(SignatureType::SubkeyBinding)
                         .set_key_flags(&KeyFlags::default()
                                        .set_encrypt_for_transport(true))?,
                     None, None)?.into());
                 p
             }).to_vec()?.into_boxed_slice()),
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

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("Certificates");
    report.add(Box::new(EncryptionKeyFlags::new()?));
    Ok(())
}
