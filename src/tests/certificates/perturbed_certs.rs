use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    packet::{key, Key, Tag},
    parse::Parse,
    serialize::SerializeInto,
    types::SignatureType,
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
        crate::tests::MESSAGE
    }
}

impl crate::plan::Runnable<TestMatrix> for PerturbedCerts {
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
        <b>M</b>arker, <b>U*</b>nbound UserID, unbound \
        <b>S*</b>ubkey, <b>B</b>ad signature, <b>O</b>dd signature, \
        <b>S</b>ubkey version<b>23</b>, \
        <b>S</b>ubkey <b>B</b>inding version<b>23</b>, \
        <b>X</b>tremely unknown packet type.</p>"
            .into()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for PerturbedCerts {
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
        let uid_unboundp = openpgp::Packet::UserID("Unbound".into());
        let uid_unbound = &uid_unboundp;
        let markerp = openpgp::Packet::Marker(Default::default());
        let marker = &markerp;

        let subkey_unbound: openpgp::Packet =
            Key::<key::PublicParts, key::SubordinateRole>::from(
                key::Key4::generate_rsa(2048)?.parts_into_public()).into();

        // Make a bad binding signature.
        let mut buf = subkeyb.to_vec()?;
        let l = buf.len();
        buf[l - 2] ^= 0xff;
        let bad_sig = openpgp::Packet::from_bytes(&buf)?;
        assert_eq!(bad_sig.kind(), Some(Tag::Signature));

        // Make an odd signature.
        buf[4] = SignatureType::Binary.into();
        let odd_sig = openpgp::Packet::from_bytes(&buf)?;
        assert_eq!(odd_sig.kind(), Some(Tag::Signature));

        // Make a fictitious new signature.
        buf[3] = 23;
        let fictitious_sig = openpgp::Packet::from_bytes(&buf)?;
        assert_eq!(fictitious_sig.tag(), Tag::Signature);

        // Make a fictitious new key.
        let mut buf = subkey.to_vec()?;
        buf[3] = 23;
        let fictitious_subkey = openpgp::Packet::from_bytes(&buf)?;
        assert_eq!(fictitious_subkey.tag(), Tag::PublicSubkey);

        // Make a fictitious new component.
        let mut unknown = openpgp::packet::Unknown::new(Tag::Unknown(59),
                                                        anyhow::anyhow!(""));
        let mut bullshit = vec![0; 659];
        openpgp::crypto::random(&mut bullshit);
        unknown.set_body(bullshit);
        let unknown = Packet::from(unknown);

        use super::make_test as make;
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
            make("P U UB UB S SB",
                 vec![primary, uid, uidb, uidb, subkey, subkeyb],
                 Some(Ok("Duplicated UserID binding".into())))?,
            make("P U UB S SB S SB",
                 vec![primary, uid, uidb, subkey, subkeyb, subkey, subkeyb],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S S SB",
                 vec![primary, uid, uidb, subkey, subkey, subkeyb],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S SB S",
                 vec![primary, uid, uidb, subkey, subkeyb, subkey],
                 Some(Ok("Duplicated subkey".into())))?,
            make("P U UB S SB SB",
                 vec![primary, uid, uidb, subkey, subkeyb, subkeyb],
                 Some(Ok("Duplicated subkey binding".into())))?,
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
            make("P U UB S SB S*",
                 vec![primary, uid, uidb, subkey, subkeyb, &subkey_unbound],
                 Some(Ok("Unbound subkey should be ignored".into())))?,
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
            make("P U UB S SB B",
                 vec![primary, uid, uidb, subkey, subkeyb, &bad_sig],
                 Some(Ok("Bad signature should be ignored".into())))?,
            make("P U UB S SB O",
                 vec![primary, uid, uidb, subkey, subkeyb, &odd_sig],
                 Some(Ok("Bad signature should be ignored".into())))?,
            make("P U UB S SB SB23",
                 vec![primary, uid, uidb, subkey, subkeyb, &fictitious_sig],
                 Some(Ok("Unknown signature version should be ignored".into())))?,
            make("P U UB S SB S23 B",
                 vec![primary, uid, uidb, subkey, subkeyb,
                      &fictitious_subkey, &bad_sig],
                 Some(Ok("Unknown key version should be ignored".into())))?,
            make("P U UB S SB X B",
                 vec![primary, uid, uidb, subkey, subkeyb, &unknown, &bad_sig],
                 Some(Ok("Unknown components should be ignored".into())))?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
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
