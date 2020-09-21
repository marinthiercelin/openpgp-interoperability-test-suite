use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    packet::{Tag, UserID, signature::SignatureBuilder},
    parse::Parse,
    serialize::Serialize,
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
        Test,
        TestMatrix,
    },
};

/// Explores how certificate expiration time is computed.
pub struct CertExpiration {
}

impl CertExpiration {
    pub fn new() -> Result<CertExpiration> {
        Ok(CertExpiration {
        })
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }
}

impl Test for CertExpiration {
    fn title(&self) -> String {
        "Certificate expiration".into()
    }

    fn description(&self) -> String {
        "<p>Explores how certificate expiration time is computed. \
        Certificate expiration is implemented by expiring the primary \
        key.  Key expiration time subpackets can be stored on direct \
        key signatures and binding signatures of the primary user id. \
        </p>\
        \
        <p>The test modifies the 'Bob' certificate so that it expires, \
        then tries to encrypt and decrypt a message with it. \
        Notation: P X U Y [U' Z] where <b>P</b>rimary key, primary \
        <b>U</b>serID, secondary <b>U'</b>serID, and <b>X</b> \
        representing key expiration time subpackets on a direct key \
        signature, <b>Y</b> on the primary userid binding signature, \
        and <b>Z</b> on the secondaray userid binding signature.  For \
        the expiration, <b>f</b> means expiration in the future, \
        <b>p</b> means expiration in the past, <b>0</b> is the \
        value 0, which means it should not expire, and <b>-</b> \
        means there is no subpacket.</p>"
            .into()
    }

    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for CertExpiration {
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
        let userid = if let Packet::UserID(uid) = uid {
            uid
        } else {
            unreachable!();
        };
        let uidb = &packets[2];
        assert_eq!(uidb.kind(), Some(Tag::Signature));
        let uidb_sig = if let Packet::Signature(sig) = uidb {
            sig
        } else {
            unreachable!();
        };
        let subkey = &packets[3];
        assert_eq!(subkey.kind(), Some(Tag::PublicSubkey));
        let subkeyb = &packets[4];
        assert_eq!(subkeyb.kind(), Some(Tag::Signature));
        let userid_secondary = UserID::from_address(Some("Secondary UserID"),
                                                    None,
                                                    "secondary@example.org")?;
        let uid_secondaryp = openpgp::Packet::UserID(userid_secondary.clone());
        let uid_secondary = &uid_secondaryp;

        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary_key = cert.primary_key().key();
        let mut primary_signer =
            primary_key.clone().parts_into_secret()?.into_keypair()?;

        use std::time::{SystemTime, Duration};
        let now = SystemTime::now();
        let past = now - Duration::new(100 * 24 * 60 * 60, 0);
        let future = now + Duration::new(100 * 24 * 60 * 60, 0);
        assert!(past < future);

        // Relative to the primary key's creation:
        let creation_time = primary_signer.public().creation_time();
        let past = past.duration_since(creation_time).unwrap();
        let future = future.duration_since(creation_time).unwrap();
        assert!(past < future);
        assert!(creation_time + past < now);
        assert!(creation_time + future > now);
        let zero = Duration::new(0, 0);

        Ok(vec![
            make("P _ U _",
                 vec![primary, uid, uidb, subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P _ U f",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P _ U 0",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(zero)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P f U _",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(future)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      uidb,
                      subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P 0 U _",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(zero)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      uidb,
                      subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P _ U _ U' f",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_primary_userid(true)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      uid_secondary,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               &userid_secondary)?
                          .into(),
                      subkey, subkeyb],
                 Some(Ok("Base case".into())))?,
            make("P _ U p",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(past)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 Some(Err("Expired".into())))?,
            make("P p U _",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(past)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      uidb,
                      subkey, subkeyb],
                 Some(Err("Expired".into())))?,
            make("P p U f",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(past)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 None)?,
            make("P f U p",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(future)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(past)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 None)?,
            make("P p U 0",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(past)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(zero)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 None)?,
            make("P 0 U p",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(zero)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(past)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      subkey, subkeyb],
                 None)?,
            make("P _ U _ U' p",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_primary_userid(true)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      uid_secondary,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               &userid_secondary)?
                          .into(),
                      subkey, subkeyb],
                 Some(Ok("Non-primary userid shouldn't expire cert".into())))?,
            make("P _ U p U' f",
                 vec![primary,
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_primary_userid(true)?
                          .set_key_validity_period(past)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      uid_secondary,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               &userid_secondary)?
                          .into(),
                      subkey, subkeyb],
                 Some(Err("Non-primary userid shouldn't override expiry".into())))?,
            make("P p U _ U' f",
                 vec![primary,
                      &SignatureBuilder::new(SignatureType::DirectKey)
                          .set_key_validity_period(past)?
                          .sign_direct_key(&mut primary_signer, primary_key)?
                          .into(),
                      uid,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_primary_userid(true)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               userid)?
                          .into(),
                      uid_secondary,
                      &SignatureBuilder::from(uidb_sig.clone())
                          .set_key_validity_period(future)?
                          .sign_userid_binding(&mut primary_signer,
                                               primary_key,
                                               &userid_secondary)?
                          .into(),
                      subkey, subkeyb],
                 Some(Err("Non-primary userid shouldn't override expiry".into())))?,
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
