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

/// Explores whether SHA-1 signatures over colliding files are
/// considered valid.
pub struct Shattered {
}

impl Shattered {
    pub fn new() -> Result<Shattered> {
        Ok(Shattered {
        })
    }
}

impl Test for Shattered {
    fn title(&self) -> String {
        "Signature over the shattered collision".into()
    }

    fn description(&self) -> String {
        "<p>This tests whether detached signatures using SHA-1 over \
         the collision from the paper <i>The first collision for full \
         SHA-1</i> are considered valid.</p>\
         \
         <p>The first test establishes a baseline.  It is a SHA-1 signature \
         over the text <code>Hello World :)</code></p>" .into() }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), data::certificate("bob.pgp").into())]
    }


    fn run(&self, implementations: &[Box<dyn OpenPGP + Sync>])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for Shattered {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        Ok(vec![
            ("Baseline".into(),
             data::message("shattered-baseline.asc").into(),
             Some(Err(
                 "Data signatures using SHA-1 should be considered invalid"
                     .into()))),
            ("SIG-1 over PDF-1".into(),
             data::message("shattered-1.pdf.asc").into(),
             Some(Err("Attack must be mitigated".into()))),
            ("SIG-1 over PDF-2".into(),
             data::message("shattered-1.pdf.asc").into(),
             Some(Err("Attack must be mitigated".into()))),
            ("SIG-2 over PDF-1".into(),
             data::message("shattered-2.pdf.asc").into(),
             Some(Err("Attack must be mitigated".into()))),
            ("SIG-2 over PDF-2".into(),
             data::message("shattered-2.pdf.asc").into(),
             Some(Err("Attack must be mitigated".into()))),
        ])

    }

    fn consume(&self, i: usize, pgp: &mut dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        let message = match i {
            0 => b"Hello World :)",
            1 | 3 => data::message("shattered-1.pdf"),
            2 | 4 => data::message("shattered-2.pdf"),
            _ => unreachable!(),
        };
        pgp.verify_detached(data::certificate("bob.pgp"), message, artifact)
    }
}
