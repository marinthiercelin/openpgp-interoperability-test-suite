use std::io::Read;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    crypto::*,
    packet::prelude::*,
    parse::{Parse, stream::*},
    types::*,
};

use crate::{
    Data,
    OpenPGP,
    Result,
    sop::SignAs,
    tests::{
        Expectation,
        TestMatrix,
        P,
        ProducerConsumerTest,
    },
};

/// Roundtrip tests check whether consume(produce(x)) yields x.
pub struct InlineSignVerifyRoundtrip {
    title: String,
    description: String,
    signer_key: Vec<u8>,
    signer_cert: Vec<u8>,
    cleartext: bool,
    recipient_key: Option<Vec<u8>>,
    recipient_cert: Option<Vec<u8>>,
    expectation: Option<Expectation>,
}

impl InlineSignVerifyRoundtrip {
    pub fn new<'r, R>(title: &str, description: &str,
                      signer_key: &[u8],
                      signer_cert: &[u8],
                      recipient_key: R,
                      recipient_cert: R,
                      expectation: Option<Expectation>)
                      -> Result<InlineSignVerifyRoundtrip>
    where
        R: Into<Option<&'r [u8]>>,
    {
        Ok(InlineSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            signer_cert: signer_cert.into(),
            signer_key: signer_key.into(),
            cleartext: false,
            recipient_key: recipient_key.into().map(|c| c.into()),
            recipient_cert: recipient_cert.into().map(|c| c.into()),
            expectation,
        })
    }

    pub fn cleartext(title: &str, description: &str,
                     signer_key: &[u8],
                     signer_cert: &[u8],
                     expectation: Option<Expectation>)
                     -> Result<InlineSignVerifyRoundtrip>
    {
        Ok(InlineSignVerifyRoundtrip {
            title: title.into(),
            description: description.into(),
            signer_cert: signer_cert.into(),
            signer_key: signer_key.into(),
            cleartext: true,
            recipient_key: None,
            recipient_cert: None,
            expectation,
        })
    }
}

impl crate::plan::Runnable<TestMatrix> for InlineSignVerifyRoundtrip {
    fn title(&self) -> String {
        self.title.clone()
    }

    fn description(&self) -> String {
        self.description.clone()
    }

    fn artifacts(&self) -> Vec<(String, Data)> {
        let mut artifacts = vec![
            ("Signer Key".into(), self.signer_key.clone().into()),
            ("Signer Certificate".into(), self.signer_cert.clone().into()),
        ];
        if let Some(a) = &self.recipient_key {
            artifacts.push(("Recipient Key".into(), a.clone().into()));
        }
        if let Some(a) = &self.recipient_cert {
            artifacts.push(("Recipient Cert".into(), a.clone().into()));
        }
        artifacts
    }

    fn run(&self, implementations: &[crate::Sop]) -> Result<TestMatrix> {
        ProducerConsumerTest::run(self, implementations)
    }
}

impl ProducerConsumerTest for InlineSignVerifyRoundtrip {
    fn produce(&self, pgp: &dyn OpenPGP)
               -> Result<Data> {
        assert_eq!(self.recipient_cert.is_none(), self.recipient_key.is_none());
        assert!(!self.cleartext || self.recipient_cert.is_none());

        if let Some(recipient) = &self.recipient_cert {
            pgp.sop()
                .encrypt()
                .signer_key(&self.signer_key)
                .cert(recipient)
                .plaintext(crate::tests::MESSAGE)
        } else {
            pgp.sop()
                .inline_sign()
                .as_(if self.cleartext {
                    SignAs::Clearsigned
                } else {
                    SignAs::Binary
                })
                .key(&self.signer_key)
                .data(crate::tests::MESSAGE)
        }
    }

    fn check_producer(&self, artifact: Data) -> Result<Data> {
        /// Given a verification result, produce the signature type.
        fn typ(r: &VerificationResult) -> SignatureType {
            use VerificationError::*;
            match r {
                Ok(v) => v.sig.typ(),
                Err(MalformedSignature { sig, .. }) => sig.typ(),
                Err(MissingKey { sig, .. }) => sig.typ(),
                Err(UnboundKey { sig, .. }) => sig.typ(),
                Err(BadKey { sig, .. }) => sig.typ(),
                Err(BadSignature { sig, .. }) => sig.typ(),
            }
        }

        struct Helper {
            key: Option<Cert>,
            cleartext: bool,
        }
        impl VerificationHelper for Helper {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                         -> Result<Vec<Cert>>
            {
                Ok(Vec::new())
            }
            fn check(&mut self, structure: MessageStructure)
                     -> Result<()>
            {
                let mut saw_signature = false;
                for (i, layer) in structure.into_iter().enumerate() {
                    match layer {
                        MessageLayer::Encryption {
                            ..
                        } if i == 0 && self.key.is_some() => (),
                        MessageLayer::Compression {
                            ..
                        } if (i == 1 && self.key.is_some())
                            || (i == 0 && ! self.key.is_some()) => (),
                        MessageLayer::SignatureGroup { ref results } => {
                            saw_signature |= ! results.is_empty();
                            if self.cleartext && ! results.iter()
                                .all(|r| typ(r) == SignatureType::Text)
                            {
                                return Err(anyhow::anyhow!(
                                    "Cleartext signature framework must use \
                                     text signatures"));
                            }
                        },
                        _ => return Err(anyhow::anyhow!(
                            "Unexpected message structure")),
                    }
                }

                if saw_signature {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("No signature found"))
                }
            }
        }
        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
                          _sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D) -> Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {
                if let Some(key) = &self.key {
                    let mut keypair = key.with_policy(P, None)?
                        .keys().for_transport_encryption()
                        .next().ok_or_else(
                            || anyhow::anyhow!("no encryption key"))?
                        .key().clone().parts_into_secret()?.into_keypair()?;

                    pkesks[0].decrypt(&mut keypair, None)
                        .map(|(algo, session_key)| decrypt(algo, &session_key));
                }
                Ok(None)
            }
        }

        let h = Helper {
            key: self.recipient_key.as_ref()
                .map(|k| Cert::from_bytes(k).unwrap()),
            cleartext: self.cleartext,
        };

        let mut content = Vec::new();
        if self.recipient_key.is_some() {
            let mut v = DecryptorBuilder::from_bytes(&artifact[..])?
                .with_policy(P, None, h)?;
            v.read_to_end(&mut content)?;
        } else {
            let mut v = VerifierBuilder::from_bytes(&artifact[..])?
                .with_policy(P, None, h)?;
            v.read_to_end(&mut content)?;
        }

        if self.cleartext {
            // Drop trailing whitespace.
            while content[content.len() - 1].is_ascii_whitespace() {
                content.pop();
            }
        }

        if &content[..] != crate::tests::MESSAGE {
            return Err(anyhow::anyhow!(
                "Bad message, expected {:?}, got {:?}",
                std::str::from_utf8(crate::tests::MESSAGE),
                std::str::from_utf8(&content)));
        }

        Ok(artifact)
    }

    fn consume(&self,
               _producer: &dyn OpenPGP,
               consumer: &dyn OpenPGP,
               artifact: &[u8])
               -> Result<Data> {
        let (verifications, message) =
            if let Some(recipient) = &self.recipient_key {
                consumer.sop()
                    .decrypt()
                    .verify_cert(&self.signer_cert)
                    .key(recipient)
                    .ciphertext_raw(artifact)?
            } else {
                consumer.sop()
                    .inline_verify()
                    .cert(&self.signer_cert)
                    .message_raw(artifact)?
            };

        let mut message = Vec::from(message);
        if self.cleartext {
            // Drop trailing whitespace.
            while message[message.len() - 1].is_ascii_whitespace() {
                message.pop();
            }
        }

        if &message[..] != crate::tests::MESSAGE {
            return Err(anyhow::anyhow!(
                "Bad message, expected {:?}, got {:?}",
                std::str::from_utf8(crate::tests::MESSAGE),
                std::str::from_utf8(&message)));
        }

        Ok(verifications)
    }

    fn expectation(&self) -> Option<Expectation> {
        self.expectation.clone()
    }
}
