use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;

use crate::{
    OpenPGP,
    Result,
    data,
    templates::Report,
    tests::{
        ProducerConsumerTest,
        asymmetric_encryption::EncryptDecryptRoundtrip,
    },
};

pub fn run(report: &mut Report, implementations: &[Box<dyn OpenPGP>])
           -> Result<()> {
    use openpgp::constants::SymmetricAlgorithm::*;
    use openpgp::constants::AEADAlgorithm::*;

    for &cipher in &[IDEA, TripleDES, CAST5, Blowfish, AES128, AES192, AES256,
                     Twofish, Camellia128, Camellia192, Camellia256] {
        report.add(
            EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         cipher),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [{:?}].", cipher),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), cipher, None)?
            .run(implementations)?)?;
    }

    for &aead_algo in &[EAX, OCB] {
        report.add(
            EncryptDecryptRoundtrip::with_cipher(
                &format!("Encrypt-Decrypt roundtrip with key 'Bob', {:?}",
                         aead_algo),
                &format!("Encrypt-Decrypt roundtrip using the 'Bob' key from \
                          draft-bre-openpgp-samples-00, modified with the \
                          symmetric algorithm preference [AES256], \
                          AEAD algorithm preference [{:?}].", aead_algo),
                openpgp::TPK::from_bytes(data::certificate("bob-secret.pgp"))?,
                b"Hello, world!".to_vec().into_boxed_slice(), AES256,
                Some(aead_algo))?
            .run(implementations)?)?;
    }

    Ok(())
}
