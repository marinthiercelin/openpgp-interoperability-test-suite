use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::*,
    types::*,
    packet::prelude::*,
    parse::Parse,
    serialize::stream::*,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    data,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

/// Tests whether implementations can use Cv25519 keys that are not in
/// canonical form.
pub struct UnclampedCv25519 {
    message: Data,
}

impl UnclampedCv25519 {
    pub fn new() -> Result<UnclampedCv25519> {
        let cert =
            openpgp::Cert::from_bytes(data::certificate("alice.pgp"))?;

        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let message = Armorer::new(message).build()?;
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption();
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;

        Ok(UnclampedCv25519 {
            message: buf.into(),
        })
    }
}

impl Test for UnclampedCv25519 {
    fn title(&self) -> String {
        "Unclamped Cv25519 secrets".into()
    }

    fn description(&self) -> String {
        "Tests whether implementations can use Cv25519 keys that are not in
         canonical form to decrypt a message.".into()
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

// function pointers:
type BytesModifier = fn(b: &mut Vec<u8>);

fn set_low_bit(b: &mut Vec<u8>) {
    // Set a verboten bit.
    b[31] |= 1;
}
fn modify_key(key:&openpgp::Cert, func:BytesModifier) -> Result<openpgp::Cert>  {
    let subkey = key.keys().subkeys().next().unwrap().key();
    let scalar = match subkey.optional_secret().unwrap() {
        key::SecretKeyMaterial::Unencrypted(m) => m.map(|mpis| {
            match mpis {
                mpi::SecretKeyMaterial::ECDH { scalar } => {
                    // OpenPGP stores the secret in reverse order.
                    const CURVE25519_SIZE: usize = 32;
                    const FIRST: usize = CURVE25519_SIZE - 1;
                    const LAST: usize = 0;

                    let mut s = scalar.value().to_vec();
                    assert_eq!(s[FIRST] & ! 0b1111_1000, 0);
                    assert_eq!(s[LAST] & 0b1100_0000, 0b0100_0000);

                    func(&mut s);

                    mpi::SecretKeyMaterial::ECDH {
                        scalar: mpi::MPI::from(s.to_vec()).into(),
                    }
                },
                o => panic!("unexpected key material: {:?}", o),
            }
        }),
        o => panic!("expected unencrypted material: {:?}", o),
    };

    let subkey_out =
        subkey.clone().add_secret(scalar.into()).0;
    return key.clone().insert_packets(Some(Packet::from(subkey_out)));
}


impl ConsumerTest for UnclampedCv25519 {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let key =
            openpgp::Cert::from_bytes(data::certificate("alice-secret.pgp"))?;

        let low_unclamped = modify_key(&key, set_low_bit)?;
        use crate::tests::certificates::make_test as make;
        Ok(vec![
            make("Base case", key.into_packets(),
                 Some(Ok("Interoperability concern".into())))?,
            make("Secret with LSB set", low_unclamped.into_packets(),
                 None)?,
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        Ok(pgp.sop().decrypt()
           .key(artifact)
           .ciphertext(&self.message)?.1)
    }

    fn check_consumer(&self, _i: usize, artifact: &[u8])
                      -> Result<()> {
        if artifact == crate::tests::MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!("Expected {:?}, got {:?}",
                                        crate::tests::MESSAGE,
                                        artifact)))
        }
    }
}
