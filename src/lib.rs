/********************************************************************************
 *   yggdrasil-keys-rs, a library for handling yggdrasil keys in rust           *
 *                                                                              *
 *   Copyright (C) 2020 Famedly GmbH                                            *
 *                                                                              *
 *   This program is free software: you can redistribute it and/or modify       *
 *   it under the terms of the GNU Affero General Public License as             *
 *   published by the Free Software Foundation, either version 3 of the         *
 *   License, or (at your option) any later version.                            *
 *                                                                              *
 *   This program is distributed in the hope that it will be useful,            *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the               *
 *   GNU Affero General Public License for more details.                        *
 *                                                                              *
 *   You should have received a copy of the GNU Affero General Public License   *
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.     *
 ********************************************************************************/
use custom_error::custom_error;
use generic_array::{typenum::consts::U64, GenericArray};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use std::convert::TryInto;
use std::net::Ipv6Addr;

const INVERTER: u8 = 255u8;
pub const IP_PREFIX: [u8; 1] = [0x02u8];

custom_error! {pub FromHexError
    WrongKeyLength                                       = "key has wrong length",
    Hex{source: hex::FromHexError}                       = "string is not valid hex: {source}",
    ConflictingPubKeys                                   = "pub keys in optional argument and included with secret key differ",
    InvalidSigKey{source: ed25519_dalek::SignatureError} = "the signature keys are invalit: {source}",
}

pub struct NodeIdentity {
    signing_keys: SigningKeys,
    encryption_keys: EncryptionKeys,
}

impl NodeIdentity {
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let signing_keys = SigningKeys::new(csprng);
        let encryption_keys = EncryptionKeys::new(csprng);
        Self {
            signing_keys,
            encryption_keys,
        }
    }

    pub fn from_hex(
        sig_sec_hex: &str,
        sig_pub_hex: Option<&str>,
        enc_sec_hex: &str,
        enc_pub_hex: Option<&str>,
    ) -> Result<Self, FromHexError> {
        let signing_keys = SigningKeys::from_hex(sig_sec_hex, sig_pub_hex)?;
        let encryption_keys = EncryptionKeys::from_hex(enc_sec_hex, enc_pub_hex)?;
        Ok(Self {
            signing_keys,
            encryption_keys,
        })
    }

    pub fn tree_id(&self) -> TreeId {
        self.signing_keys.tree_id()
    }

    pub fn node_id(&self) -> NodeId {
        self.encryption_keys.node_id()
    }
}

/// ed25519 keypair
pub struct SigningKeys(ed25519_dalek::Keypair);

impl SigningKeys {
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self(ed25519_dalek::Keypair::generate(csprng))
    }
    pub fn from_hex(sig_sec_hex: &str, sig_pub_hex: Option<&str>) -> Result<Self, FromHexError> {
        let (secret, public) = hex_pair_to_bytes(sig_sec_hex, sig_pub_hex)?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&secret)?;
        let public = match public {
            Some(public) => ed25519_dalek::PublicKey::from_bytes(&public)?,
            None => ed25519_dalek::PublicKey::from(&secret),
        };
        Ok(Self(ed25519_dalek::Keypair { secret, public }))
    }

    pub fn to_hex_split(&self) -> (String, String) {
        let secret_bytes = self.0.secret.as_bytes();
        let public_bytes = self.0.public.as_bytes();
        (
            format!("{:x?}", secret_bytes),
            format!("{:x?}", public_bytes),
        )
    }

    pub fn to_hex_joined(&self) -> String {
        let secret_bytes = self.0.secret.as_bytes();
        let public_bytes = self.0.public.as_bytes();
        format!("{:x?}{:x?}", secret_bytes, public_bytes)
    }

    pub fn tree_id(&self) -> TreeId {
        TreeId(Sha512::digest(self.0.public.as_bytes()))
    }
}

/// curve25519 keypair
pub struct EncryptionKeys {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl EncryptionKeys {
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let secret = x25519_dalek::StaticSecret::new(csprng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_hex(enc_sec_hex: &str, enc_pub_hex: Option<&str>) -> Result<Self, FromHexError> {
        let (secret, public) = hex_pair_to_bytes(enc_sec_hex, enc_pub_hex)?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public = match public {
            Some(public) => x25519_dalek::PublicKey::from(public),
            None => x25519_dalek::PublicKey::from(&secret),
        };
        Ok(Self { secret, public })
    }

    pub fn to_hex_split(&self) -> (String, String) {
        let secret_bytes = self.secret.to_bytes();
        let public_bytes = self.public.as_bytes();
        (
            format!("{:x?}", secret_bytes),
            format!("{:x?}", public_bytes),
        )
    }

    pub fn to_hex_joined(&self) -> String {
        let secret_bytes = self.secret.to_bytes();
        let public_bytes = self.public.as_bytes();
        format!("{:x?}{:x?}", secret_bytes, public_bytes)
    }

    pub fn node_id(&self) -> NodeId {
        NodeId(Sha512::digest(self.public.as_bytes()))
    }
}

pub struct NodeId(GenericArray<u8, U64>);
impl NodeId {
    const ADDR_BYTE : u8 = 0xfeu8;
    const SNET_BYTE : u8 = 0x01u8;
    pub fn strength(&self) -> u32 {
        leading_ones(&self.0)
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn address_with_prefix(&self, prefix: &[u8]) -> Ipv6Addr {
        Ipv6Addr::from(self.address_bytes(prefix, false))
    }
    pub fn subnet_with_prefix(&self, prefix: &[u8]) -> Ipv6Addr {
        Ipv6Addr::from(self.address_bytes(prefix, true))
    }
    fn address_bytes(&self, prefix: &[u8], net: bool) -> [u8; 16] {
        // Prefix must be at most a /48 for subnets or /112 for addresses
        assert!(prefix.len() <= if net { 6 } else { 14 });
        let mut bytes : [u8; 16] = [0u8; 16];
        bytes[0..prefix.len()].copy_from_slice(prefix);
        bytes[prefix.len() - 1] = if net { 
            bytes[prefix.len() - 1] | Self::SNET_BYTE
        } else {
            bytes[prefix.len() - 1] & Self::ADDR_BYTE
        };
        let (ones, remainder) = strip_ones(&self.0);
        bytes[prefix.len()] = ones as u8;
        let end = if net { 8 } else { 16 };
        bytes[(prefix.len() + 1)..end].copy_from_slice(&remainder[0..(end - (prefix.len() + 1))]);
        bytes
    }
    pub fn address(&self) -> Ipv6Addr {
        self.address_with_prefix(&IP_PREFIX)
    }
    pub fn subnet(&self) -> Ipv6Addr {
        self.subnet_with_prefix(&IP_PREFIX)
    }
}
pub struct TreeId(GenericArray<u8, U64>);
impl TreeId {
    pub fn strength(&self) -> u32 {
        leading_ones(&self.0)
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

pub(crate) fn leading_ones(sha512: &GenericArray<u8, U64>) -> u32 {
    let mut leading_ones = 0u32;
    while (leading_ones / 8) < 64 {
        let current_byte = sha512[(leading_ones / 8) as usize];
        // This inversion is not necessary, leading_ones() does exist. It is nightly only for
        // now though, so we'll keep it for now.
        let inverted_byte = current_byte ^ INVERTER;
        let local_leading_ones = inverted_byte.leading_zeros();
        leading_ones += local_leading_ones;
        // Break if there's a one in the byte
        if local_leading_ones != 8 {
            break;
        }
    }
    leading_ones
}

pub(crate) fn strip_ones(sha512: &GenericArray<u8, U64>) -> (u32, Vec<u8>) {
    let ones = leading_ones(sha512);
    let shift = ((ones % 8u32) + 1u32) as u8;
    // Cut away everything we'd drop anyway
    let slice = &sha512.as_slice()[((ones / 8u32) as usize)..];
    let mut vec = Vec::new();
    for i in 0..slice.len() - 2 {
        let lhs: u8 = slice[i] << shift;
        let rhs: u8 = slice[i + 1] >> (8u8 - shift);
        vec.push(lhs | rhs);
    }
    vec.push(slice[slice.len() - 1] << shift);
    (ones, vec)
}

pub(crate) fn hex_pair_to_bytes(
    secret: &str,
    public: Option<&str>,
) -> Result<([u8; 32], Option<[u8; 32]>), FromHexError> {
    let sec_bytes = hex::decode(secret)?;
    let (sec_bytes, pub_bytes): ([u8; 32], Option<[u8; 32]>) = match sec_bytes.len() {
        64 => {
            let pub_bytes = sec_bytes[32..].try_into().unwrap();
            let sec_bytes = sec_bytes[0..32].try_into().unwrap();
            (sec_bytes, Some(pub_bytes))
        }
        32 => (sec_bytes[0..32].try_into().unwrap(), None),
        _ => return Err(FromHexError::WrongKeyLength),
    };

    let pub_bytes: Option<[u8; 32]> = match pub_bytes {
        Some(pub_bytes) => match public {
            Some(pub_hex) => {
                let pub_bytes_from_option = &hex::decode(pub_hex)?[0..32];
                if pub_bytes != pub_bytes_from_option {
                    return Err(FromHexError::ConflictingPubKeys);
                } else {
                    Some(pub_bytes)
                }
            }
            None => Some(pub_bytes),
        },
        None => match public {
            Some(pub_hex) => {
                let pub_bytes = hex::decode(pub_hex)?;
                match pub_bytes.len() {
                    32 => Some(pub_bytes[0..32].try_into().unwrap()),
                    _ => return Err(FromHexError::WrongKeyLength),
                }
            }
            None => None,
        },
    };
    Ok((sec_bytes, pub_bytes))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    const ENC_PUB_HEX: &'static str =
        "551e45e3e871bf843be66a9188f7e229f198e685f169ee2dface9dcd2e518661";
    const ENC_SEC_HEX: &'static str =
        "04b3287a12837cbed0a9e235e2db1a7a300d4b7bdb63079da0e320090b898020";

    const NODE_ID_HEX : &'static str = "fffff21bbdda03246ea9f855be6eeeaf1baf809dc151e0f82ffcac1be3cec5f4ce0953ddccf8b3202bf20eb96779822992710d201e07cb5721b66e9d02f54707";

    const SIG_PUB_HEX: &'static str =
        "40a40d9fc1a8727994b54c8e416329e9f71596a97d2912be80daf5bf20da4a3d";
    const SIG_SEC_HEX : &'static str = "de1f6a91c14d6e8e9a204e4926c75d4d114500a422041a8c603054dc43605e6a40a40d9fc1a8727994b54c8e416329e9f71596a97d2912be80daf5bf20da4a3d";

    const TREE_ID_HEX : &'static str = "ffff4252ce2cd427d22a4ead1e75fb2bfa21e193b8615c55a091a7607eb6a7d3a9c60548ca9dc2f93c64f400fe6d16d917102de0e5959d61c0e3d4e43f9cd23b";

    const ADDR: Ipv6Addr = Ipv6Addr::new(
        0x0214, 0x4377, 0xbb40, 0x648d, 0xd53f, 0x0ab7, 0xcddd, 0xd5e3,
    );
    const SNET: Ipv6Addr = Ipv6Addr::new(
        0x0314, 0x4377, 0xbb40, 0x648d, 0x0000, 0x0000, 0x0000, 0x0000,
    );

    #[test]
    fn test_ygg_key_parsing_and_strength() {
        let identity = crate::NodeIdentity::from_hex(
            SIG_SEC_HEX,
            Some(SIG_PUB_HEX),
            ENC_SEC_HEX,
            Some(ENC_PUB_HEX),
        )
        .unwrap();
        let node_id = identity.node_id();
        let tree_id = identity.tree_id();
        assert_eq!(node_id.to_hex(), NODE_ID_HEX);
        assert_eq!(tree_id.to_hex(), TREE_ID_HEX);
        assert_eq!(node_id.strength(), 20);
        assert_eq!(tree_id.strength(), 16);
    }

    #[test]
    fn test_ygg_addr_generation() {
        let identity = crate::NodeIdentity::from_hex(
            SIG_SEC_HEX,
            Some(SIG_PUB_HEX),
            ENC_SEC_HEX,
            Some(ENC_PUB_HEX),
        )
        .unwrap();
        let node_id = identity.node_id();
        assert_eq!(node_id.address(), ADDR);
        assert_eq!(node_id.subnet(), SNET);
    }
}
