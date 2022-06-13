use std::io::Write;

use anyhow::Context;

use nettle::{
    random::Yarrow,
    rsa,
};
use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    armor,
    crypto::mpi::{self, *},
    packet::prelude::*,
    parse::Parse,
    serialize::stream::*,
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

/// Tests asymmetric encryption corner cases.
pub struct RSAKeySizes {
    sig: Data,
}

impl RSAKeySizes {
    pub fn new() -> Result<RSAKeySizes> {
        /// Creates a signature with Bob's (encryption) subkey.
        ///
        /// XXX: This should be shared.
        fn signature() -> Result<Vec<u8>> {
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
            signer.write_all(crate::tests::MESSAGE)?;
            signer.finalize()?;
            Ok(sig)
        }

        Ok(RSAKeySizes {
            sig: signature()?.into(),
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for RSAKeySizes {
    fn title(&self) -> String {
        "RSA key sizes".into()
    }

    fn description(&self) -> String {
        "<p>
RSA keys can differ wildly in size.  This test checks which ones are
accepted by different implementations, from way too small to way too
big, including some odd sizes.
</p>".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Signature".into(), self.sig.clone())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for RSAKeySizes {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        // Start from Bob's certificate, replace the primary key, use
        // encryption subkey as signing subkey.
        let mut rng = Yarrow::default();
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;

        let creation_time = cert.primary_key().creation_time();
        let userid = cert.userids().nth(0).unwrap().userid().clone();
        let subkey = cert.keys().subkeys().nth(0).unwrap().key().clone();
        let mut subkey_signer =
            subkey.clone().parts_into_secret()?.into_keypair().unwrap();

        let mut make_test = |test, bits, expectation| {
            let hash_algo = HashAlgorithm::SHA256;

            let primary_packet =
                crate::data::file(&format!("rsa-keys/{}k.pgp", bits / 1024))
                .map(|b| openpgp::PacketPile::from_bytes(b).unwrap()
                     .into_children().next().unwrap())
                .unwrap_or_else(|| {
                    let (public, private) =
                        rsa::generate_keypair(&mut rng, bits).unwrap();

                    let (p, q, u) = private.as_rfc4880();
                    let public_mpis = PublicKey::RSA {
                        e: MPI::new(&*public.e()),
                        n: MPI::new(&*public.n()),
                    };
                    let private_mpis = mpi::SecretKeyMaterial::RSA {
                        d: MPI::new(&*private.d()).into(),
                        p: MPI::new(&*p).into(),
                        q: MPI::new(&*q).into(),
                        u: MPI::new(&*u).into(),
                    };

                    let primary: Key<_, key::PrimaryRole> =
                        Key4::<_, key::PrimaryRole>::with_secret(
                            creation_time,
                            PublicKeyAlgorithm::RSAEncryptSign,
                            public_mpis,
                            private_mpis.into()).unwrap().into();
                    primary.into()
                });

            let primary =
                if let openpgp::Packet::SecretKey(s) = primary_packet.clone() {
                    s
                } else {
                    unreachable!()
                };
            let cert = Cert::from_packets(std::iter::once(primary_packet.clone()))?;
            let mut primary_signer = primary.clone().into_keypair()?;

            // Make a new binding and mark the primary key as only
            // certification capable.
            let userid_binding =
                userid.bind(
                    &mut primary_signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_hash_algo(hash_algo)
                        .set_signature_creation_time(creation_time)?
                        .set_key_flags(KeyFlags::empty()
                                       .set_certification())?
                        .set_features(Features::empty().set_mdc())?
                        .set_preferred_hash_algorithms(
                            vec![HashAlgorithm::SHA256])?
                        .set_preferred_symmetric_algorithms(
                            vec![SymmetricAlgorithm::AES256])?)?;

            crate::tests::make_test(
                test,
                vec![
                    primary_packet,
                    userid.clone().into(),
                    userid_binding.into(),
                    //subkey.clone().into(),
                    subkey.clone().parts_into_secret()?.into(),
                    subkey.bind(
                        &mut primary_signer, &cert,
                        SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_hash_algo(hash_algo)
                            .set_signature_creation_time(creation_time)?
                            .set_key_flags(KeyFlags::empty().set_signing())?
                        // We need to create a primary key binding signature.
                            .set_embedded_signature(
                                SignatureBuilder::new(
                                    SignatureType::PrimaryKeyBinding)
                                    .set_hash_algo(hash_algo)
                                    .set_signature_creation_time(creation_time)?
                                    .sign_primary_key_binding(
                                        &mut subkey_signer,
                                        &primary,
                                        &subkey)?)?)?
                        .into(),
                ],
                armor::Kind::SecretKey,
                expectation)
        };
        Ok(vec![
            make_test("2k", 2048, Some(Ok("Base case".into())))?,
            make_test("512", 512, Some(Err("Too small".into())))?,
            make_test("768", 768, Some(Err("Too small".into())))?,
            make_test("1k - 1", 1024 - 1, Some(Err("Too small".into())))?,
            make_test("1k", 1024, Some(Err("Too small".into())))?,
            make_test("1k + 1", 1024 + 1, Some(Err("Too small".into())))?,
            make_test("1k + 256", 1024 + 256, Some(Err("Too small".into())))?,
            make_test("1k + 512", 1024 + 512, Some(Err("Too small".into())))?,
            make_test("2k - 2", 2048 - 2, None)?,
            make_test("2k - 1", 2048 - 1, None)?,
            make_test("2k + 1", 2048 + 1, Some(Ok("Interoperability concern".into())))?,
            make_test("3k - 2", 3072 - 2, Some(Ok("Interoperability concern".into())))?,
            make_test("3k - 1", 3072 - 1, Some(Ok("Interoperability concern".into())))?,
            make_test("3k", 3072, Some(Ok("Interoperability concern".into())))?,
            make_test("3k + 1", 3072 + 1, Some(Ok("Interoperability concern".into())))?,
            make_test("4032", 4032, Some(Ok("Interoperability concern".into())))?,
            make_test("4064", 4064, Some(Ok("Interoperability concern".into())))?,
            make_test("4072", 4072, Some(Ok("Interoperability concern".into())))?,
            make_test("4k", 2u32.pow(12), Some(Ok("Interoperability concern".into())))?,
            make_test("8k", 2u32.pow(13), None)?,
            make_test("16k", 2u32.pow(14), None)?,
            make_test("32k", 2u32.pow(15), None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let sig = pgp.sop()
            .sign()
            .key(artifact)
            .data(crate::tests::MESSAGE)
            .context("Signing failed")?;
        pgp.sop()
            .verify()
            .cert(&crate::tests::extract_cert(artifact)?)
            .signatures(&sig)
            .data_raw(crate::tests::MESSAGE)
            .context("Verification failed")?;
        Ok(crate::tests::MESSAGE.to_vec().into())
    }
}
