use crate::{
    sop,
    Sop,
    Result,
};

/// Chunks of data.
#[derive(Clone, Debug, Default)]
pub struct Data(Box<[u8]>);

impl std::ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data(v.into())
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        v.to_vec().into()
    }
}

impl From<Data> for Vec<u8> {
    fn from(v: Data) -> Self {
        v.0.into()
    }
}

use serde::{Serializer, Deserializer, de::{Error as _}};
impl serde::Serialize for Data {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer
    {
        s.serialize_str(&base64::encode(self))
    }
}

impl<'de> serde::Deserialize<'de> for Data {
    fn deserialize<D>(d: D) -> std::result::Result<Data, D::Error>
    where D: Deserializer<'de>
    {
        let s = String::deserialize(d)?;
        base64::decode(s)
            .map(Into::into)
            .map_err(D::Error::custom)
    }
}

/// Abstract OpenPGP interface.
///
/// This is the old abstraction for drivers.  We now only have only
/// one driver, SOP, and in the future, all tests should directly use
/// the SOP interface.
///
/// In the mean time, we provide a method `sop()` that returns the SOP
/// interface.
pub trait OpenPGP: std::fmt::Debug {
    fn sop(&self) -> &Sop;
    fn version(&self) -> Result<sop::Version>;
    fn encrypt(&self, recipient: &[u8], plaintext: &[u8]) -> Result<Data>;
    fn decrypt(&self, recipient: &[u8], ciphertext: &[u8]) -> Result<Data>;
    fn sign_detached(&self, _signer: &[u8], _data: &[u8]) -> Result<Data>;
    fn verify_detached(&self, _signer: &[u8], _data: &[u8], _sig: &[u8])
                       -> Result<Data>;
    fn generate_key(&self, _userids: &[&str]) -> Result<Data>;
}
