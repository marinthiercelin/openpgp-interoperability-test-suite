use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    packet::Tag,
    parse::Parse,
    serialize::Serialize,
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
/// perturbations and permutations.
pub struct PerturbedCerts {
}

impl PerturbedCerts {
    pub fn new() -> Result<PerturbedCerts> {
        Ok(PerturbedCerts {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for PerturbedCerts {
    fn title(&self) -> String {
        "Perturbed certificates".into()
    }

    fn description(&self) -> String {
        "<p>Explores how robust the certificate canonicalization is to \
        perturbations and permutations.  While these certificates may \
        not strictly adhere to the structure outlined in Section 12.1 \
        of RFC4880, handling them gracefully improves the user \
        experience.</p>\
        \
        <p>Notation: <b>P</b>rimary key, <b>U</b>serID, <b>U</b>serID \
        <b>B</b>inding, <b>S</b>ubkey, <b>S</b>ubkey <b>B</b>inding, \
        <b>M</b>arker.<b>U*</b>nbound UserID.</p>"
            .into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PerturbedCerts {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        // Makes tests.
        fn make(test: &str, packets: Vec<&Packet>,
                expectation: Option<Expectation>)
                -> Result<(String, Data, Option<Expectation>)>
        {
            let mut buf = Vec::new();
            {
                use openpgp::armor;
                let mut w =
                    armor::Writer::new(&mut buf, armor::Kind::PublicKey)?;
                for p in packets {
                    p.serialize(&mut w)?;
                }
                w.finalize()?;
            }
            Ok((test.into(), buf.into(), expectation))
        };

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
        let uid_unboundp = openpgp::Packet::UserID("Unbound".into());
        let uid_unbound = &uid_unboundp;
        let markerp = openpgp::Packet::Marker(Default::default());
        let marker = &markerp;

        Ok(vec![
            make("P U UB S SB",
                 vec![primary, uid, uidb, subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P U UB U UB S SB",
                 vec![primary, uid, uidb, uid, uidb, subkey, subkeyb],
                 Some(Ok("Duplicated UserID".into())))?,
            make("P U U UB S SB",
                 vec![primary, uid, uid, uidb, subkey, subkeyb],
                 Some(Ok("Duplicated UserID".into())))?,
            make("P U UB U S SB",
                 vec![primary, uid, uidb, uid, subkey, subkeyb],
                 Some(Ok("Duplicated UserID".into())))?,
            make("P U UB S SB S SB",
                 vec![primary, uid, uidb, subkey, subkeyb, subkey, subkeyb],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S S SB",
                 vec![primary, uid, uidb, subkey, subkey, subkeyb],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S SB S",
                 vec![primary, uid, uidb, subkey, subkeyb, subkey],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S",
                 vec![primary, uid, uidb, subkey],
                 Some(Err("Subkey not bound".into())))?,
            make("P U S SB",
                 vec![primary, uid, subkey, subkeyb],
                 None)?,
            make("P S SB",
                 vec![primary, subkey, subkeyb],
                 None)?,
            make("P U UB U* S SB",
                 vec![primary, uid, uidb, uid_unbound, subkey, subkeyb],
                 Some(Ok("Unbound UserID should be ignored".into())))?,
            make("P M U UB S SB",
                 vec![primary, marker, uid, uidb, subkey, subkeyb],
                 Some(Ok("Marker packet MUST be ignored".into())))?,
            make("P U M UB S SB",
                 vec![primary, uid, marker, uidb, subkey, subkeyb],
                 Some(Ok("Marker packet MUST be ignored".into())))?,
            make("P U UB S M SB",
                 vec![primary, uid, uidb, subkey, marker, subkeyb],
                 Some(Ok("Marker packet MUST be ignored".into())))?,
            make("P U S UB SB",
                 vec![primary, uid, subkey, uidb, subkeyb],
                 None)?,
            make("P UB SB U S",
                 vec![primary, uidb, subkeyb, uid, subkey],
                 None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &mut OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let ciphertext = pgp.encrypt(artifact, self.message())?;
        pgp.decrypt(data::certificate("bob-secret.pgp"), &ciphertext)
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
