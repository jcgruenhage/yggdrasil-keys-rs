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
use generic_array::{GenericArray, typenum::consts::U64};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use std::net::Ipv6Addr;

use crate::{
    FromHexError,
    helper::{
        hex_pair_to_bytes,
        leading_ones,
        strip_ones
    }
};

/// Represents a node in the yggdrasil network. Contains two key pairs,
/// one for signatures and one for encryption.
///
/// The keys in here are as defined in [YS001: Yggdrasil Core Specification],
/// with the supplied methods matching the spec as close as possible.
/// Address generation isn't specced yet, so it's been adapted from the source code
/// in [yggdrasil-go] for address generation.
///
/// [yggdrasil-go]: https://github.com/yggdrasil-network/yggdrasil-go
/// [YS001: Yggdrasil Core Specification]: https://github.com/yggdrasil-network/yggdrasil-specs/blob/ys001/ys001-yggdrasil-core-specification.md
pub struct NodeIdentity {
    /// ed25519 key pair, used as yggdrasil signing keys
    pub signing_keys: SigningKeys,
    /// curve25519 key pair, used as yggdrasil encryption keys
    pub encryption_keys: EncryptionKeys,
}

impl NodeIdentity {
    /// Generates two new key pairs using the supplied CSPRNG
    ///
    /// ```rust
    /// use rand::thread_rng;
    /// use std::net::Ipv6Addr;
    /// use yggdrasil_keys::NodeIdentity;
    ///
    /// let node = NodeIdentity::new(&mut thread_rng());
    /// let address : Ipv6Addr = node.node_id().into();
    /// ```
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let signing_keys = SigningKeys::new(csprng);
        let encryption_keys = EncryptionKeys::new(csprng);
        Self {
            signing_keys,
            encryption_keys,
        }
    }

    /// Parses hexadecimally encoded keypairs.
    ///
    /// Arguments:
    ///  * `sec_hex`: Either 32 hex encoded bytes for the secret key,
    ///  or 64 hex encoded bytes for the keypair
    ///  * `pub_hex`: Optionally, 32 hex encoded bytes for the public key
    ///
    /// Arguments like these exist for both the encryption and signing keys,
    /// and they work like this:
    ///  - You have to supply the secret key.
    ///  - You can supply the public key, but you don't have to.
    ///  If it's missing, one will be generated from the secret key.
    ///  - If you pass a keypair to the `sec_hex` argument,
    ///  and additionally a public key to the `pub_hex` argument,
    ///  the two keys will be compared. If they differ, the function returns an error.
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

    /// Convenience wrapper around [`SigningKeys::tree_id`]
    pub fn tree_id(&self) -> TreeId {
        self.signing_keys.tree_id()
    }

    /// Convenience wrapper around [`EncryptionKeys::node_id`]
    pub fn node_id(&self) -> NodeId {
        self.encryption_keys.node_id()
    }
}

/// Yggdrasil signing keys, using ed25519, for building a spanning tree
pub struct SigningKeys(ed25519_dalek::Keypair);

impl SigningKeys {
    /// Generate new signing keys using the supplied CSPRNG
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self(ed25519_dalek::Keypair::generate(csprng))
    }

    /// Parse encryption keys from hex `String`(s).
    ///
    /// For details, see [`NodeIdentity::from_hex`](crate::NodeIdentity::from_hex).
    pub fn from_hex(sig_sec_hex: &str, sig_pub_hex: Option<&str>) -> Result<Self, FromHexError> {
        let (secret, public) = hex_pair_to_bytes(sig_sec_hex, sig_pub_hex)?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&secret)?;
        let public = match public {
            Some(public) => ed25519_dalek::PublicKey::from_bytes(&public)?,
            None => ed25519_dalek::PublicKey::from(&secret),
        };
        Ok(Self(ed25519_dalek::Keypair { secret, public }))
    }

    /// Hex-encode the secret and public keys into a String each
    pub fn to_hex_split(&self) -> (String, String) {
        let secret_bytes = self.0.secret.as_bytes();
        let public_bytes = self.0.public.as_bytes();
        (
            hex::encode(secret_bytes),
            hex::encode(public_bytes),
        )
    }

    /// Hex-encode the keypair into a combined String
    pub fn to_hex_joined(&self) -> String {
        let (secret, public) = self.to_hex_split();
        format!("{}{}", secret, public)
    }

    /// Calculate the Tree ID for this keypair.
    pub fn tree_id(&self) -> TreeId {
        TreeId(Sha512::digest(self.0.public.as_bytes()))
    }
}

/// Yggdrasil encryption keys, using curve25519, for encrypting traffic
pub struct EncryptionKeys {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl EncryptionKeys {
    /// Generate new encryption keys using the supplied CSPRNG
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let secret = x25519_dalek::StaticSecret::new(csprng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Parse encryption keys from hex `String`(s).
    ///
    /// For details, see [`NodeIdentity::from_hex`](crate::NodeIdentity::from_hex).
    pub fn from_hex(enc_sec_hex: &str, enc_pub_hex: Option<&str>) -> Result<Self, FromHexError> {
        let (secret, public) = hex_pair_to_bytes(enc_sec_hex, enc_pub_hex)?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let public = match public {
            Some(public) => x25519_dalek::PublicKey::from(public),
            None => x25519_dalek::PublicKey::from(&secret),
        };
        Ok(Self { secret, public })
    }

    /// Hex-encode the secret and public keys into a String each
    pub fn to_hex_split(&self) -> (String, String) {
        let secret_bytes = self.secret.to_bytes();
        let public_bytes = self.public.as_bytes();
        (
            hex::encode(secret_bytes),
            hex::encode(public_bytes),
        )
    }

    /// Hex-encode the keypair into a combined String
    pub fn to_hex_joined(&self) -> String {
        let (secret, public) = self.to_hex_split();
        format!("{}{}", secret, public)
    }

    /// Calculate the Node ID for this keypair.
    pub fn node_id(&self) -> NodeId {
        NodeId(Sha512::digest(self.public.as_bytes()))
    }
}

/// The Node ID is a 64-byte identifier which is calculated by taking the SHA512 sum of the node's public encryption key. The node's permanent address is derived from the Node ID.
pub struct NodeId(GenericArray<u8, U64>);
impl NodeId {
    const ADDR_BYTE : u8 = 0xfeu8;
    const SNET_BYTE : u8 = 0x01u8;
    /// This prefix is taken from [yggdrasil-go](yggdrasil-go),
    /// it's the one currently used in the yggdrasil network,
    /// namely `200::/7`.
    ///
    /// [yggdrasil-go]: https://github.com/yggdrasil-network/yggdrasil-go
    pub const IP_PREFIX: [u8; 1] = [0x02u8];

    /// The "strength" of a given Node ID is the number of leading one bits set.
    pub fn strength(&self) -> u32 {
        leading_ones(&self.0)
    }

    /// Hex-encodes the Tree ID
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Calculate the address for this Node ID with the given IP prefix.
    pub fn address_with_prefix(&self, prefix: &[u8]) -> Ipv6Addr {
        Ipv6Addr::from(self.address_bytes(prefix, false))
    }

    /// Calculate the `/64` subnet for this Node ID with the given IP prefix.
    pub fn subnet_with_prefix(&self, prefix: &[u8]) -> Ipv6Addr {
        Ipv6Addr::from(self.address_bytes(prefix, true))
    }

    /// Calculate the address bytes.
    fn address_bytes(&self, prefix: &[u8], net: bool) -> [u8; 16] {
        // Prefix must be at most a /48 for subnets or /112 for addresses
        assert!(prefix.len() <= if net { 6 } else { 14 });

        // Create 16 bytes array and copy the prefix into it
        let mut bytes : [u8; 16] = [0u8; 16];
        bytes[0..prefix.len()].copy_from_slice(prefix);

        // Set the last bit of the prefix to one if its a subnet,
        // or zero if its an address
        bytes[prefix.len() - 1] = if net { 
            bytes[prefix.len() - 1] | Self::SNET_BYTE
        } else {
            bytes[prefix.len() - 1] & Self::ADDR_BYTE
        };

        // Count the leading ones in the Node ID,
        // and strip them plus the following zero.
        let (ones, remainder) = strip_ones(&self.0);

        // Set the next byte to the the number of ones stripped from the Node ID
        bytes[prefix.len()] = ones as u8;

        // Set the remaining bytes until the end of the address/subnet
        // to the remainder of the Node ID
        let end = if net { 8 } else { 16 };
        bytes[(prefix.len() + 1)..end].copy_from_slice(&remainder[0..(end - (prefix.len() + 1))]);

        // Return the address bytes
        bytes
    }

    /// Calculate the address for this Node ID with the default IP prefix.
    pub fn address(&self) -> Ipv6Addr {
        self.address_with_prefix(&Self::IP_PREFIX)
    }

    /// Calculate the `/64` subnet for this Node ID with the default IP prefix.
    pub fn subnet(&self) -> Ipv6Addr {
        self.subnet_with_prefix(&Self::IP_PREFIX)
    }
}

impl std::convert::Into<Ipv6Addr> for NodeId {
    fn into(self) -> Ipv6Addr {
        self.address()
    }
}

/// The Tree ID is a 64-byte identifier which is calculated by taking the SHA512 sum of the node's public signing key.
pub struct TreeId(GenericArray<u8, U64>);
impl TreeId {
    /// The "strength" of a given Tree ID is the number of leading one bits set.
    pub fn strength(&self) -> u32 {
        leading_ones(&self.0)
    }

    /// Hex-encodes the Tree ID
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
