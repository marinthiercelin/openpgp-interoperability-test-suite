//! Tests revocations and binding signatures over time.
//!
//! These tests create a certificate with a signing capable primary
//! key (subkey), and revoke it later on, then re-legitimize it using
//! a new signature.  We then ask sqv to verify a signature at
//! different points in time.  Hard revocations of the key invalidate
//! the signature at any point in time, whereas in the case of soft
//! revocations, the keys can be re-legitimized.
//!
//! All tests are run in three flavors:
//!
//!  0. The primary key makes the signatures and is revoked.
//!  1. The subkey makes the signatures, primary key is revoked.
//!  2. The subkey makes the signatures and is revoked.
//!
//! As extra subtlety, we bind the subkey *after* the t1-t2 signature.
//!
//! Timeline:   v
//!             |
//!         t0 -| - Signature revoked-key-sig-t0.pgp
//!             |
//!         t1 -| - Primary key creation
//!             |
//!             | - Subkey creation
//!             |
//!             | - Signature revoked-key-sig-t1-t2.pgp
//!             |
//!             | - Subkey is bound
//!             |
//!         t2 -| - Revocation of (sub)key
//!             |
//!             | - Signature revoked-key-sig-t2-t3.pgp
//!             |
//!         t3 -| - New direct/binding signature
//!             |
//!             | - Signature revoked-key-sig-t3-now.pgp
//!             |
//!        now -|
//!             v

use crate::{
    Data,
    OpenPGP,
    Result,
    plan::TestPlan,
    tests::{
        Expectation,
        Test,
        TestMatrix,
        ConsumerTest,
    },
};

#[derive(Copy, Clone)]
enum Flavor {
    PrimarySigns,
    SubkeySignsPrimaryRevoked,
    SubkeySignsSubkeyRevoked,
}

impl Flavor {
    fn subkey_signs(&self) -> bool {
        use self::Flavor::*;
        match self {
            PrimarySigns => false,
            _ => true,
        }
    }

    fn signing_key(&self) -> &'static str {
        if self.subkey_signs() {
            "subkey"
        } else {
            "primary key"
        }
    }

    fn revoked_key(&self) -> &'static str {
        use self::Flavor::*;
        match self {
            SubkeySignsSubkeyRevoked => "subkey",
            _ => "primary key",
        }
    }
}

impl std::fmt::Display for Flavor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Flavor::*;
        write!(f, "{}", match self {
            PrimarySigns => "primary key signs and is revoked",
            SubkeySignsPrimaryRevoked => "subkey signs, primary key is revoked",
            SubkeySignsSubkeyRevoked => "subkey signs, subkey is revoked",
        })
    }
}

#[derive(Copy, Clone)]
enum Revoked {
    NotRevoked,
    NoSubpacket,
    Unspecified,
    Compromised,
    Private,
    Unknown,
    Superseded,
    KeyRetired,
    UidRetired,
}

impl Revoked {
    fn hard(&self) -> Option<bool> {
        use self::Revoked::*;
        match self {
            NotRevoked => None,
            NoSubpacket => Some(true),
            Unspecified => Some(true),
            Compromised => Some(true),
            Private => Some(true),
            Unknown => Some(true),
            Superseded => Some(false),
            KeyRetired => Some(false),
            UidRetired => Some(false),
        }
    }

    fn is_revoked(&self) -> bool {
        use self::Revoked::*;
        match self {
            NotRevoked => false,
            _ => true,
        }
    }

    fn tag(&self) -> &'static str {
        use self::Revoked::*;
        match self {
            NotRevoked => "not-revoked",
            NoSubpacket => "revoked-no_subpacket",
            Unspecified => "revoked-unspecified",
            Compromised => "revoked-compromised",
            Private => "revoked-private",
            Unknown => "revoked-unknown",
            Superseded => "revoked-superseded",
            KeyRetired => "revoked-key_retired",
            UidRetired => "revoked-uid_retired",
        }
    }
}

impl std::fmt::Display for Revoked {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Revoked::*;
        write!(f, "{}", match self {
            NotRevoked => "not revoked",
            NoSubpacket => "revoked: no subpacket",
            Unspecified => "revoked: unspecified",
            Compromised => "revoked: compromised",
            Private => "revoked: private",
            Unknown => "revoked: unknown",
            Superseded => "revoked: superseded",
            KeyRetired => "revoked: key retired",
            UidRetired => "revoked: uid retired",
        })
    }
}

struct RevokedKey {
    flavor: Flavor,
    revoked: Revoked,
}

impl RevokedKey {
    pub fn new(flavor: Flavor, revoked: Revoked) -> Result<RevokedKey> {
        Ok(RevokedKey { flavor, revoked, })
    }

    /// Returns the message that is signed in this test.
    ///
    /// Note: This test uses pre-built artifacts that use a slightly
    /// different message.
    pub fn message(&self) -> &'static str {
        "Hello, World"
    }

    fn key(&self) -> &'static [u8] {
        let key = if let Flavor::SubkeySignsSubkeyRevoked = self.flavor {
            format!("{}.sk", self.revoked.tag())
        } else {
            self.revoked.tag().to_string()
        };
        crate::data::file(&format!("revoked-key/revoked-key-cert-{}.pgp", key))
            .unwrap()
    }

    fn sig(&self, t: &str) -> Data {
        let sig = if let Flavor::PrimarySigns = self.flavor {
            t.to_string()
        } else {
            format!("{}.sk", t)
        };
        crate::data::file(&format!("revoked-key/revoked-key-sig-{}.pgp", sig))
            .unwrap()
            .into()
    }
}

impl Test for RevokedKey {
    fn title(&self) -> String {
        if let Revoked::NotRevoked = self.revoked {
            let flavor = self.flavor.to_string();
            format!("Key revocation test: {}not revoked (base case)",
                    &flavor[..flavor.len() - "revoked".len()])
        } else {
            format!("Key revocation test: {}; {}", self.flavor, self.revoked)
        }
    }

    fn description(&self) -> String {
        format!("
<p>This test uses a certificate with a signing capable {1} that is
evolving over time.  Later on, the {2} is revoked and then
re-legitimized using a new signature.  We then ask implementations to
verify a signature at different points in time.  Hard revocations of
the key invalidate the signature at any point in time, whereas in the
case of soft revocations, the keys can be re-legitimized.{3}<p>

<p>
  In this particular test, the {2} is {0}.
  The signed message is <code>{4}</code>
  {5}
</p>

<pre>
Timeline:   v
            |
        t0 -| - Creation time of first signature
            |
        t1 -| - Primary key creation
            |
            | - Subkey creation
            |
     t1-t2 -| - Creation time of second signature
            |
            | - Subkey is bound
            |
        t2 -| - Revocation of {1}
            |
     t2-t3 -| - Creation time of third signature
            |
        t3 -| - {1} is re-legitimized
            |
    t3-now -| - Creation time of fourth signature
            |
       now -|
            v
</pre>
",
                self.revoked,
                self.flavor.signing_key(),
                self.flavor.revoked_key(),
                match self.revoked.hard() {
                    None => "",
                    Some(true) => "  This is a hard revocation, all signatures \
                                   must be considered invalid.",
                    Some(false) => "  This is a soft revocation, so the key \
                                    may be re-legitimized after which \
                                    signatures should be considered valid \
                                    again.",
                },
                self.message(),
                if let Flavor::PrimarySigns = self.flavor {
                    ""
                } else {
                    "  As extra subtlety, we bind the subkey *after* the \
                     t1-t2 signature.  Therefore, the t1-t2 signature must \
                     be considered invalid."
                },
        )
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        vec![("Certificate".into(), self.key().into())]
    }

    fn run(&self, implementations: &[crate::Sop])
           -> Result<TestMatrix> {
        ConsumerTest::run(self, implementations)
    }
}

impl ConsumerTest for RevokedKey {
    fn produce(&self) -> Result<Vec<(String, Data, Option<Expectation>)>> {
        let make = |test: &str, e: Option<Expectation>|
                   -> (String, Data, Option<Expectation>)
        {
            (test.into(), self.sig(test), e)
        };

        Ok(vec![
            make("t0", Some(Err("Signature predates primary key.".into()))),
            make("t1-t2", if self.revoked.hard().unwrap_or(false) {
                Some(Err("Hard revocations invalidate key at all times."
                         .into()))
            } else if self.flavor.subkey_signs() {
                Some(Err("Subkey is not bound at this time.".into()))
            } else {
                Some(Ok("Key is valid at this time.".into()))
            }),
            make("t2-t3", if self.revoked.hard().unwrap_or(false) {
                Some(Err("Hard revocations invalidate key at all times."
                         .into()))
            } else if self.revoked.is_revoked() {
                Some(Err("Key is revoked at this time.".into()))
            } else {
                Some(Ok("Key is valid at this time.".into()))
            }),
            make("t3-now", if self.revoked.hard().unwrap_or(false) {
                Some(Err("Hard revocations invalidate key at all times."
                         .into()))
            } else {
                Some(Ok("Key is valid at this time.".into()))
            }),
        ])
    }

    fn consume(&self, _i: usize, pgp: &dyn OpenPGP, artifact: &[u8])
               -> Result<Data> {
        pgp.verify_detached(self.key(), self.message().as_bytes(), artifact)
    }
}

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    use self::Flavor::*;
    use self::Revoked::*;

    plan.add_section("Revocations");
    plan.add(Box::new(RevokedKey::new(PrimarySigns, NotRevoked)?));
    plan.add(Box::new(RevokedKey::new(SubkeySignsPrimaryRevoked, NotRevoked)?));

    for &revocation in &[NoSubpacket,
                         Unspecified,
                         Compromised,
                         Private,
                         Unknown,
                         Superseded,
                         KeyRetired,
                         UidRetired] {
        for &flavor in &[PrimarySigns,
                         SubkeySignsPrimaryRevoked,
                         SubkeySignsSubkeyRevoked] {
            plan.add(Box::new(RevokedKey::new(flavor, revocation)?));
        }
    }

    Ok(())
}
