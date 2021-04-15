use std::io::Write;
use std::time::{Duration, SystemTime};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    Cert,
    types::{
        Features,
        HashAlgorithm,
        KeyFlags,
        ReasonForRevocation,
        SignatureType,
        SymmetricAlgorithm,
    },
    packet::signature::{
        SignatureBuilder,
    },
    parse::Parse,
    serialize::SerializeInto,
    serialize::stream::*,
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

/// Tests whether expiration on binding signatures and revocation
/// signatures are honored.
pub struct TemporaryValidity {
    bob: Cert,
    certs: Vec<Data>,
}

lazy_static::lazy_static! {
    static ref D_2WEEKS: Duration = Duration::new(60 * 60 * 24 * 14, 0);
    static ref D_MONTH:  Duration = Duration::new(60 * 60 * 24 * 28, 0);
}

impl TemporaryValidity {
    pub fn new() -> Result<TemporaryValidity> {
        let mut t = TemporaryValidity {
            bob:
            openpgp::Cert::from_bytes(data::certificate("bob-secret.pgp"))?,
            certs: Vec::with_capacity(0),
        };

        t.certs = vec![
            t.cert_a()?,
            t.cert_b()?,
            t.cert_c()?,
        ];
        Ok(t)
    }

    fn message(&self) -> &'static [u8] {
        "Hello World :)".as_bytes()
    }

    fn signature(&self, at: SystemTime) -> Result<Data> {
        let cert = &self.bob;
        let signing_keypair =
            cert.keys().nth(0).unwrap()
            .key().clone().parts_into_secret()?.into_keypair()?;

        let mut sig = Vec::new();
        let message = Message::new(&mut sig);
        let message = Armorer::new(message)
            .kind(armor::Kind::Signature)
            .build()?;
        let b = SignatureBuilder::new(SignatureType::Binary);
        let mut signer = Signer::with_template(message, signing_keypair, b)
            .creation_time(at)
            .detached()
            .build()?;
        signer.write_all(self.message())?;
        signer.finalize()?;
        Ok(sig.into())
    }

    fn t0(&self) -> SystemTime {
        self.t1() - *D_2WEEKS
    }

    fn t1(&self) -> SystemTime {
        self.bob.primary_key().creation_time()
    }

    fn t1_t2(&self) -> SystemTime {
        self.t1() + *D_2WEEKS
    }

    fn t2(&self) -> SystemTime {
        self.t1() + *D_MONTH
    }

    fn t2_t3(&self) -> SystemTime {
        self.t2() + *D_2WEEKS
    }

    fn t3(&self) -> SystemTime {
        self.t1() + 2 * *D_MONTH
    }

    fn t3_now(&self) -> SystemTime {
        self.t3() + *D_2WEEKS
    }

    fn cert_a(&self) -> Result<Data> {
        let key = &self.bob;
        let primary = key.primary_key().key().clone();
        let mut primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;
        let userid = key.userids().nth(0).unwrap().userid().clone();

        let userid_binding_t1 =
            userid.bind(
                &mut primary_signer, &key,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(self.t1())?
                    .set_signature_validity_period(*D_MONTH)?
                    .set_key_flags(KeyFlags::empty().set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let userid_binding_t3 =
            userid.bind(
                &mut primary_signer, &key,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(self.t3())?
                    .set_key_flags(KeyFlags::empty().set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;

        Cert::from_packets(vec![
            primary.into(),
            userid.into(),
            userid_binding_t1.into(),
            userid_binding_t3.into(),
        ].into_iter())?.armored().to_vec().map(Into::into)
    }

    fn cert_b(&self) -> Result<Data> {
        let key = &self.bob;
        let primary = key.primary_key().key().clone();
        let mut primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;
        let userid = key.userids().nth(0).unwrap().userid().clone();

        let userid_binding_t1 =
            userid.bind(
                &mut primary_signer, &key,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(self.t1())?
                    .set_key_flags(KeyFlags::empty().set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let userid_revocation_t2 =
            userid.bind(
                &mut primary_signer, &key,
                SignatureBuilder::new(SignatureType::CertificationRevocation)
                    .set_signature_creation_time(self.t2())?
                    .set_signature_validity_period(*D_MONTH)?
                    .set_reason_for_revocation(ReasonForRevocation::UIDRetired,
                                               "Temporary suspension")?)?;
        Cert::from_packets(vec![
            primary.into(),
            userid.into(),
            userid_binding_t1.into(),
            userid_revocation_t2.into(),
        ].into_iter())?.armored().to_vec().map(Into::into)
    }

    fn cert_c(&self) -> Result<Data> {
        let key = &self.bob;
        let primary = key.primary_key().key().clone();
        let mut primary_signer =
            primary.clone().parts_into_secret()?.into_keypair()?;
        let userid = key.userids().nth(0).unwrap().userid().clone();

        let userid_binding_t1 =
            userid.bind(
                &mut primary_signer, &key,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(self.t1())?
                    .set_key_flags(KeyFlags::empty().set_signing())?
                    .set_features(Features::empty().set_mdc())?
                    .set_preferred_hash_algorithms(
                        vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512])?
                    .set_preferred_symmetric_algorithms(
                        vec![SymmetricAlgorithm::AES256])?)?;
        let revocation_t2 =
            SignatureBuilder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(self.t2())?
                .set_signature_validity_period(*D_MONTH)?
                .set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                           "Temporary suspension")?
                .sign_direct_key(&mut primary_signer, None)?;

        Cert::from_packets(vec![
            primary.into(),
            userid.into(),
            userid_binding_t1.into(),
            revocation_t2.into(),
        ].into_iter())?.armored().to_vec().map(Into::into)
    }
}

impl Test for TemporaryValidity {
    fn title(&self) -> String {
        "Temporary validity".into()
    }

    fn description(&self) -> String {
        format!("
<p>This test uses a certificate with a signing capable primary key
that is evolving over time.  The certificate is constructed so that it
is valid for a month, then not valid for a month, then valid for month
again.</p>

<p>We then verify signatures made in these periods to probe whether
implementations consider the certificate valid at this point in
time.</p>

<p>There are three variants of this test.  In the first variant A, we
use expiring userid binding signatures.  In the second variant B, the
userid is bound for the whole time, but we temporarily revoke it using
expiring revocation signatures.  The third variant C is similar, but
we temporarily revoke the certificate.</p>

<p>The signature is over the string <code>{}</code>.</p>

<pre>
Timeline:
        v                                       A                 B, C
        |                              |                 |                    |
    t0 -| Creation of first signature  |                 |                    |
        |                              |                 |                    |
    t1 -| Certificate creation         |                 |                    |
        |                              |                 |                    |
 t1-t2 -| Creation of second signature |                 |                    |
        |                              |                 |                    |
    t2 -| Validity ends temporarily    | Binding expires | Revocation         |
        |                              |                 |                    |
 t2-t3 -| Creation of third signature  |                 |                    |
        |                              |                 |                    |
    t3 -| Validity restored            | New binding     | Revocation expires |
        |                              |                 |                    |
t3-now -| Creation of fourth signature |                 |                    |
        |                              |                 |                    |
   now -|                              |                 |                    |
        v
</pre>
",
                String::from_utf8(self.message().into()).unwrap())
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![
            ("Cert A".into(), self.certs[0].clone()),
            ("Cert B".into(), self.certs[1].clone()),
            ("Cert C".into(), self.certs[2].clone()),
        ]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for TemporaryValidity {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let sig_t0 = self.signature(self.t0())?;
        let sig_t1_t2 = self.signature(self.t1_t2())?;
        let sig_t2_t3 = self.signature(self.t2_t3())?;
        let sig_t3_now = self.signature(self.t3_now())?;

        Ok(vec![
            ("Cert A, sig t0".into(),
             sig_t0.clone(),
             Some(Err("Signature predates key creation time".into()))),
            ("Cert A, sig t1-t2".into(),
             sig_t1_t2.clone(),
             Some(Ok("Cert is valid".into()))),
            ("Cert A, sig t2-t3".into(),
             sig_t2_t3.clone(),
             Some(Err("Cert is not valid".into()))),
            ("Cert A, sig t2-now".into(),
             sig_t3_now.clone(),
             Some(Ok("Cert is valid again".into()))),
            ("Cert B, sig t0".into(),
             sig_t0.clone(),
             Some(Err("Signature predates key creation time".into()))),
            ("Cert B, sig t1-t2".into(),
             sig_t1_t2.clone(),
             Some(Ok("Cert is valid".into()))),
            ("Cert B, sig t2-t3".into(),
             sig_t2_t3.clone(),
             Some(Err("Primary key is not signing-capable".into()))),
            ("Cert B, sig t2-now".into(),
             sig_t3_now.clone(),
             Some(Ok("Cert is valid again".into()))),
            ("Cert C, sig t0".into(),
             sig_t0.clone(),
             Some(Err("Signature predates key creation time".into()))),
            ("Cert C, sig t1-t2".into(),
             sig_t1_t2.clone(),
             Some(Ok("Cert is valid".into()))),
            ("Cert C, sig t2-t3".into(),
             sig_t2_t3.clone(),
             Some(Err("Cert is revoked".into()))),
            ("Cert C, sig t2-now".into(),
             sig_t3_now.clone(),
             Some(Ok("Cert is valid again".into()))),
        ])
    }

    fn consume(&self, i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let cert = &*self.certs[i / 4];
        // XXX: Unfortunately, we need to use data_raw for now
        // because many implementations emit malformed time stamps
        // (and the DATE type is somewhat underspecified).
        pgp.sop().verify().certs(vec![cert]).signatures(artifact)
            .data_raw(self.message())
    }
}
