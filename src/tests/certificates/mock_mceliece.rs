use std::{
    convert::TryInto,
    io::Write,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::mpi,
    Packet,
    packet::{key, Key, Tag, signature::SignatureBuilder},
    parse::Parse,
    serialize::Marshal,
    types::*,
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
    signature: Vec<u8>,
}

impl MockMcEliece {
    pub fn new() -> Result<MockMcEliece> {
        use openpgp::{
            armor::Kind,
            serialize::stream::*,
        };

        // Get the primary signer.
        let bob =
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?;
        let primary_signer = bob.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        let mut signature = Vec::new();
        let message = Message::new(&mut signature);
        let message = Armorer::new(message).kind(Kind::Signature).build()?;
        let mut signer = Signer::new(message, primary_signer)
            .detached().build()?;
        signer.write_all(crate::tests::MESSAGE)?;
        signer.finalize()?;

        Ok(MockMcEliece {
            signature,
        })
    }
}

impl Test for MockMcEliece {
    fn title(&self) -> String {
        "Mock PQ subkey".into()
    }

    fn description(&self) -> String {
        format!("\
<p>Explores how robust the certificate canonicalization is to huge
encryption subkeys that cannot be MPI encoded.  While these keys are
not functional, we can check whether they can coexist with classical
keys so that we can have an upgrade path.</p>

<p>The test verifies a signature with a certificate containing a mock
key using an unsupported algorithm or curve.  The signature is made
using the primary key over the message <code>{}</code>.  The mock
subkey is not involved in any way, besides being present in the
certificate.</p>

<p>The test explores two dimensions.  On the one hand is the algorithm
choice, on the other the parameter representation.  The algorithms
are:

<ul>
<li>Unknown asymmetric algorithm</li>
<li>ECDSA with an unknown curve</li>
<li>EdDSA with an unknown curve</li>
<li>ECDH with an unknown curve</li>
</ul>
</p>

<p>The algorithm-specific data for each of these unknowable subkeys
vary between:

<ul>
<li>a series of well-formed MPIs</li>
<li>reasonable-sized data (not in MPI format)</li>
<li>huge data (unrepresentable as MPI)</li>
</ul>
</p>
",
                String::from_utf8_lossy(crate::tests::MESSAGE),
        )
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Bob's cert".into(), data::certificate("bob.pgp").into()),
            ("Signature".into(), self.signature.clone().into()),
        ]
    }

    fn run(&self, implementations: &[crate::Sop])
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
        let creation_time =
            bob.keys().subkeys().nth(0).unwrap().creation_time();
        let bob_subkey = bob.keys().subkeys().next().unwrap().key();

        // The algorithm-specific data for each of these unknowable subkeys
        // would vary between:
        //
        //  - a series of well-formed MPIs.
        //  - reasonable-sized data (not in MPI format), and
        //  - huge data (unrepresentable as MPI),

        // MPI.
        let one_mpis_pub = mpi::PublicKey::Unknown {
            mpis: (0..1).map(|_| {
                let mut data = vec![0; 2048 / 8];
                openpgp::crypto::random(&mut data);
                data.into()
            }).collect(),
            rest: Default::default(),
        };
        let two_mpis_pub = mpi::PublicKey::Unknown {
            mpis: (0..2).map(|_| {
                let mut data = vec![0; 2048 / 8];
                openpgp::crypto::random(&mut data);
                data.into()
            }).collect(),
            rest: Default::default(),
        };

        // dkg: Monkeysphere controls the 1.3.6.1.4.1.37210 OID
        // prefix. We can use 1.3.6.1.4.1.37210.99 as a "phony
        // Elliptic curve" OID for this test.
        const MONKEYCURVE: [u8; 11] =
            [0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x5A, 0x63];

        // Reasonable.
        let reasonable_pub = mpi::PublicKey::Unknown {
            mpis: Default::default(),
            rest: {
                let mut data = vec![0; 2048 / 8 * 2];
                openpgp::crypto::random(&mut data);
                data.into()
            },
        };

        // Huge. Make a plausible mock McEliece subkey.  See here for
        // the size:
        // https://pqcrypto.eu.org/docs/initial-recommendations.pdf
        let mut mceliece_pub = vec![0; (8_373_911 + 8) / 8];
        openpgp::crypto::random(&mut mceliece_pub);
        let mceliece_pub = mpi::PublicKey::Unknown {
            mpis: Default::default(),
            rest: mceliece_pub.into(),
        };

        let mut tests = Vec::new();
        let mut make = |test: String,
                        encryption,
                        subkey: Key<key::PublicParts, key::SubordinateRole>,
                        expectation|
        {
            let binding = subkey.bind(
                &mut primary_signer,
                &bob,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_signature_creation_time(creation_time)?
                    .set_key_flags(
                        if encryption {
                            KeyFlags::empty()
                                .set_storage_encryption()
                                .set_transport_encryption()
                        } else {
                            KeyFlags::empty()
                                .set_authentication()
                        })?)?;

            let subkey: Packet = subkey.into();
            let binding: Packet = binding.into();

            super::make_test(test,
                             vec![primary, uid, uidb, &subkey, &binding],
                             expectation)
        };

        // So that should result in 12 test vectors, the cross product of the
        // three algo-specific data formats crossed with a subkey with:
        //
        //  - unknown algo
        //  - ECDSA w/unknown curve
        //  - EdDSA w/unknown curve
        //  - ECDH w/unknown curve

        // Base case.
        tests.push(make("Bob's cert".into(), true, bob_subkey.clone().into(),
                        Some(Ok("Base case.".into())))?);

        // Unknown algorithm.
        for (desc, bits) in &[("MPI encoding", &two_mpis_pub),
                              ("opaque encoding, small", &reasonable_pub),
                              ("opaque encoding, big", &mceliece_pub)]
        {
            let subkey: Key::<key::PublicParts, key::SubordinateRole> =
                key::Key4::<key::PublicParts, key::SubordinateRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::Unknown(99),
                    (*bits).clone(),
                )?.into();
            tests.push(make(format!("Unknown algo, {}", desc),
                            true, subkey,
                            Some(Ok("Interoperability concern.".into())))?);
        }

        // Unknown ECDSA curve.
        for (desc, bits) in &[("MPI encoding", &one_mpis_pub),
                              ("opaque encoding, small", &reasonable_pub),
                              ("opaque encoding, big", &mceliece_pub)]
        {
            let ecdsa_bits = mpi::PublicKey::Unknown {
                mpis: Default::default(),
                rest: {
                    let mut buf = Vec::new();
                    // One octet curve length.
                    buf.push(MONKEYCURVE.len().try_into().unwrap());
                    // Curve OID.
                    buf.extend_from_slice(&MONKEYCURVE);
                    // The public bits.
                    bits.serialize(&mut buf)?;
                    buf.into()
                },
            };
            let subkey: Key::<key::PublicParts, key::SubordinateRole> =
                key::Key4::<key::PublicParts, key::SubordinateRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDSA,
                    ecdsa_bits,
                )?.into();
            tests.push(make(format!("ECDSA, unknown curve, {}", desc),
                            false, subkey,
                            Some(Ok("Interoperability concern.".into())))?);
        }

        // Unknown EdDSA curve.
        for (desc, bits) in &[("MPI encoding", &one_mpis_pub),
                              ("opaque encoding, small", &reasonable_pub),
                              ("opaque encoding, big", &mceliece_pub)]
        {
            let eddsa_bits = mpi::PublicKey::Unknown {
                mpis: Default::default(),
                rest: {
                    let mut buf = Vec::new();
                    // One octet curve length.
                    buf.push(MONKEYCURVE.len().try_into().unwrap());
                    // Curve OID.
                    buf.extend_from_slice(&MONKEYCURVE);
                    // The public bits.
                    bits.serialize(&mut buf)?;
                    buf.into()
                },
            };
            let subkey: Key::<key::PublicParts, key::SubordinateRole> =
                key::Key4::<key::PublicParts, key::SubordinateRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::EdDSA,
                    eddsa_bits,
                )?.into();
            tests.push(make(format!("EdDSA, unknown curve, {}", desc),
                            false, subkey,
                            Some(Ok("Interoperability concern.".into())))?);
        }

        // Unknown ECDH curve.
        for (desc, bits) in &[("MPI encoding", &one_mpis_pub),
                              ("opaque encoding, small", &reasonable_pub),
                              ("opaque encoding, big", &mceliece_pub)]
        {
            let ecdh_bits = mpi::PublicKey::Unknown {
                mpis: Default::default(),
                rest: {
                    let mut buf = Vec::new();
                    // One octet curve length.
                    buf.push(MONKEYCURVE.len().try_into().unwrap());
                    // Curve OID.
                    buf.extend_from_slice(&MONKEYCURVE);
                    // The public bits.
                    bits.serialize(&mut buf)?;
                    // KDF parameter length.
                    buf.push(3);
                    // Reserved.
                    buf.push(0x01);
                    // Hash algorithm.
                    buf.push(HashAlgorithm::SHA512.into());
                    // Cipher algorithm.
                    buf.push(SymmetricAlgorithm::AES256.into());

                    buf.into()
                },
            };
            let subkey: Key::<key::PublicParts, key::SubordinateRole> =
                key::Key4::<key::PublicParts, key::SubordinateRole>::new(
                    creation_time,
                    PublicKeyAlgorithm::ECDH,
                    ecdh_bits,
                )?.into();
            tests.push(make(format!("ECDH, unknown curve, {}", desc),
                            true, subkey,
                            Some(Ok("Interoperability concern.".into())))?);
        }

        Ok(tests)
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.sop().verify()
            .cert(artifact)
            .signatures(&self.signature)
            .data_raw(crate::tests::MESSAGE)
    }
}
