use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    packet::signature::SignatureBuilder,
    parse::Parse,
    types::{KeyFlags, SignatureType},
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

/// Explores a certificate corner case where a certificate includes
/// its primary key as subkey.
pub struct ImMyOwnGrandpa {
}

impl ImMyOwnGrandpa {
    pub fn new() -> Result<ImMyOwnGrandpa> {
        Ok(ImMyOwnGrandpa {
        })
    }

    fn message(&self) -> &'static [u8] {
        crate::tests::MESSAGE
    }
}

impl Test for ImMyOwnGrandpa {
    fn title(&self) -> String {
        "I'm My Own Grandpa".into()
    }

    fn description(&self) -> String {
        "<p>Explores a certificate corner case where a certificate \
         includes its primary key as subkey.  This is an oddball, \
         supporting it is not necessary.</p>\
         \
         <p>A certificate is constructed by taking Bob's subkey and \
         using it as primary key as well as subkey.  The test encrypts \
         a short message, and tries to decrypt is using Bob's key.</p>"
            .into()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for ImMyOwnGrandpa {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let bob =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let uid =
            bob.userids().nth(0).unwrap().userid().clone();
        let uidb =
            bob.userids().nth(0).unwrap().self_signatures()
                .nth(0).unwrap().clone();
        let key = bob.keys().subkeys().nth(0).unwrap().key().clone();
        let mut signer =
            key.clone().parts_into_secret()?.into_keypair()?;
        let sub_key = key.clone().take_secret().0;
        let primary_key = sub_key.clone().role_into_primary();

        let cert = openpgp::Cert::from_packets(
            vec![primary_key.clone().into()].into_iter())?;

        use super::make_test as make;
        Ok(vec![
            make("I'm My Own Grandpa",
                 vec![Packet::from(primary_key.clone()),
                      uid.clone().into(),
                      uid.bind(
                          &mut signer,
                          &cert,
                          uidb.into())?.into(),
                      sub_key.clone().into(),
                      sub_key.bind(
                          &mut signer,
                          &cert,
                          SignatureBuilder::new(SignatureType::SubkeyBinding)
                              .set_signature_creation_time(
                                  sub_key.creation_time())?
                              .set_key_flags(KeyFlags::empty()
                                             .set_storage_encryption()
                                             .set_transport_encryption())?
                      )?.into(),
                 ],
                 None)?,
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
