use std::io::Write;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::mpi::*,
    packet::prelude::*,
    parse::Parse,
    types::SymmetricAlgorithm,
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
pub struct RSAEncryption {}

impl RSAEncryption {
    pub fn new() -> RSAEncryption {
        RSAEncryption {}
    }
}

impl crate::plan::Runnable<TestMatrix> for RSAEncryption {
    fn title(&self) -> String {
        "RSA encryption corner cases".into()
    }

    fn description(&self) -> String {
        "<p>
RSA ciphertext can vary in size.  This creates an opportunity for
mishandling of buffers, e.g. <a
href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3580\">CVE-2021-3580</a>.
</p>".into()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("TSK".into(), data::certificate("bob-secret.pgp").into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for RSAEncryption {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        use openpgp::serialize::stream::*;

        // RSA.
        let cert =
            openpgp::Cert::from_bytes(data::certificate("bob.pgp"))?;

        // The base case.
        let mut buf = Vec::new();
        let message = Message::new(&mut buf);
        let recipients =
            cert.keys().with_policy(crate::tests::P, None)
            .for_transport_encryption();
        let message = Encryptor::for_recipients(message, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(crate::tests::MESSAGE)?;
        message.finalize()?;

        let pp = openpgp::PacketPile::from_bytes(&buf)?;
        assert_eq!(pp.children().count(), 2);
        let pkesk = pp.path_ref(&[0]).unwrap();
        let pkesk_s =
            if let Packet::PKESK(p) =
                pkesk { p } else { panic!() };
        let rsa_c =
            if let Ciphertext::RSA { c } =
                pkesk_s.esk() { c } else { panic!() };
        let seip = pp.path_ref(&[1]).unwrap();

        let make_test = |test, packets, expectation| {
            crate::tests::make_test(test, packets,
                                    openpgp::armor::Kind::Message,
                                    expectation)
        };
        Ok(vec![
            make_test("Base case", vec![pkesk.clone(), seip.clone()],
                      Some(Ok("Interoperability concern".into())))?,
            make_test("zero ciphertext", vec![
                {
                    let mut p = pkesk_s.clone();
                    p.set_esk(Ciphertext::RSA { c: vec![].into() });
                    p.into()
                },
                seip.clone(),
            ], Some(Ok("Must fail (gracefully!)".into())))?,

            make_test("ciphertext - 1 bit", vec![
                {
                    let mut p = pkesk_s.clone();
                    let mut c = rsa_c.value().to_vec();
                    // Clear one bit in the MSB, and set the next one.
                    match c[0].leading_zeros() {
                        7 => {
                            // Underflow.
                            c[0] &= !1;
                            assert_eq!(c[0], 0);
                            // Set bit in the next byte.
                            c[1] |= 1 << 7;
                        },
                        8 =>
                            panic!("leading zero byte in MPI"),
                        n => {
                            assert!(n < 7);
                            c[0] &= !(1 << (7 - n));
                            // Set the next bit.
                            c[0] |= 1 << (7 - n - 1);
                        },
                    }
                    p.set_esk(Ciphertext::RSA { c: c.into() });
                    p.into()
                },
                seip.clone(),
            ], Some(Ok("Must fail (gracefully!)".into())))?,

            // XXX: This has a chance to succeed due to the
            // modulo-arithmetic in RSA.
            //make_test("ciphertext + 1 bit", vec![
            //    {
            //        let mut p = pkesk_s.clone();
            //        let mut c = rsa_c.value().to_vec();
            //        // Set one more bit in the MSB.
            //        match c[0].leading_zeros() {
            //            0 => // Overflow.  Need a new MSB.
            //                c.insert(0, 0x01),
            //            8 =>
            //                panic!("leading zero byte in MPI"),
            //            n => {
            //                // Set the bit.
            //                assert!(n < 8);
            //                c[0] |= 1 << (7 - n);
            //            },
            //        }
            //        p.set_esk(Ciphertext::RSA { c: c.into() });
            //        p.into()
            //    },
            //    seip.clone(),
            //], Some(Ok("Must fail (gracefully!)".into())))?,

            make_test("ciphertext - 8 bit", vec![
                {
                    let mut p = pkesk_s.clone();
                    let mut c = rsa_c.value().to_vec();
                    c.pop();
                    p.set_esk(Ciphertext::RSA { c: c.into() });
                    p.into()
                },
                seip.clone(),
            ], Some(Ok("Must fail (gracefully!)".into())))?,

            make_test("ciphertext + 8 bit", vec![
                {
                    let mut p = pkesk_s.clone();
                    let mut c = rsa_c.value().to_vec();
                    c.push(255);
                    p.set_esk(Ciphertext::RSA { c: c.into() });
                    p.into()
                },
                seip.clone(),
            ], Some(Ok("Must fail (gracefully!)".into())))?,

            make_test("ciphertext + 1 MSB", vec![
                {
                    let mut p = pkesk_s.clone();
                    let mut c = rsa_c.value().to_vec();
                    c.insert(0, 255);
                    p.set_esk(Ciphertext::RSA { c: c.into() });
                    p.into()
                },
                seip.clone(),
            ], Some(Ok("Must fail (gracefully!)".into())))?,
        ])
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let r = pgp.sop()
            .decrypt()
            .key(data::certificate("bob-secret.pgp"))
            .ciphertext(artifact);
        if i == 0 {
            // base case
            Ok(r?.1)
        } else {
            // inspect the error more closely!

            // XXX: this is the wrong place to do that.  we should
            // have something like check_consumer, that operates on
            // the Result<_> of consume().

            use crate::sop::{ErrorWithOutput, SOPError};
            use std::ops::Deref;
            match r {
                Ok(v) => Err(anyhow::anyhow!(
                    "Expected an error, but got success: {:?}", v)),
                Err(e) => match e.downcast_ref::<ErrorWithOutput>().unwrap().deref() {
                    SOPError::Signal(_) => Err(e),
                    SOPError::IoError(_) => Err(e),
                    _ => Ok(b"failed gracefully".to_vec().into()),
                },
            }
        }
    }

    fn check_consumer(&self, i: usize, artifact: &[u8]) -> Result<()> {
        if i == 0 {
            // Base case.
            if &artifact[..] == crate::tests::MESSAGE {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Expected {:?}, got {:?}",
                                    crate::tests::MESSAGE, artifact))
            }
        } else {
            // No checks.
            Ok(())
        }
    }
}
