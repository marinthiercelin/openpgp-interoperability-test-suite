use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::mpi,
    Packet,
    packet::{key, Key, Tag, signature::SignatureBuilder},
    parse::Parse,
    types::{
        KeyFlags,
        PublicKeyAlgorithm,
        SignatureType,
    },
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

/// Explores how robust the certificate canonicalization is to
/// huge encryption subkeys that cannot be MPI encoded.
pub struct MockMcEliece {
}

impl MockMcEliece {
    pub fn new() -> Result<MockMcEliece> {
        Ok(MockMcEliece {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for MockMcEliece {
    fn title(&self) -> String {
        "Mock PQ encryption subkey".into()
    }

    fn description(&self) -> String {
        "<p>Explores how robust the certificate canonicalization is to \
        huge encryption subkeys that cannot be MPI encoded.  While these \
        keys are not functional, we can check whether they can coexist \
        with classical keys so that we can have an upgrade path.</p>\
        \
        <p>This test squats public key algorithm identifier \
        <code>99</code>, because it is unlikely to be ever used in practice, \
        yet is a plausible algorithm below the private namespace.</p>"
            .into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for MockMcEliece {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let packets =
            openpgp::PacketPile::from_bytes(data::certificate("bob.pgp"))?
            .into_children().collect::<Vec<_>>();
        assert_eq!(packets.len(), 5);
        let primary = &packets[0];
        assert_eq!(primary.kind(), Some(Tag::PublicKey));
        let uid = &packets[1];
        assert_eq!(uid.kind(), Some(Tag::UserID));
        let uidb = &packets[2];
        assert_eq!(uidb.kind(), Some(Tag::Signature));
        let subkey = &packets[3];
        assert_eq!(subkey.kind(), Some(Tag::PublicSubkey));
        let subkeyb = &packets[4];
        assert_eq!(subkeyb.kind(), Some(Tag::Signature));

        // Get the primary signer.
        let bob =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let mut primary_signer = bob.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        // Make a plausible mock McEliece subkey.

        // First, make up some key material.  See here for the size:
        // https://pqcrypto.eu.org/docs/initial-recommendations.pdf
        let mut mceliece_pub = vec![0; (8_373_911 + 8) / 8];
        openpgp::crypto::random(&mut mceliece_pub);

        let creation_time =
            bob.keys().subkeys().nth(0).unwrap().creation_time();
        let mceliece: Key::<key::PublicParts, key::SubordinateRole> =
            key::Key4::<key::PublicParts, key::SubordinateRole>::new(
                creation_time,
                PublicKeyAlgorithm::Unknown(99),
                mpi::PublicKey::Unknown {
                    mpis: Default::default(),
                    rest: mceliece_pub.into(),
                })?.into();
        let mcelieceb = mceliece.bind(
            &mut primary_signer,
            &bob,
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(creation_time)?
                .set_key_flags(KeyFlags::empty()
                               .set_storage_encryption()
                               .set_transport_encryption())?)?;

        let mceliece: Packet = mceliece.into();
        let mcelieceb: Packet = mcelieceb.into();

        use super::make_test as make;
        Ok(vec![
            make("Bob's cert",
                 vec![primary, uid, uidb, subkey, subkeyb],
                 Some(Ok("Base case.".into())))?,
            make("RSA, Mock McEliece",
                 vec![primary, uid, uidb,
                      subkey, subkeyb, &mceliece, &mcelieceb],
                 Some(Ok("Interoperability concern.".into())))?,
            make("Mock McEliece, RSA",
                 vec![primary, uid, uidb,
                      &mceliece, &mcelieceb, subkey, subkeyb],
                 Some(Ok("Interoperability concern.".into())))?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(artifact, self.message())?;
        pgp.new_context()?
            .decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == self.message() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                self.message(), artifact))
        }
    }
}
