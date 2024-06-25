/********************************************************************************
 *   yggdrasil-keys-rs, a library for handling yggdrasil keys in rust           *
 *                                                                              *
 *   Copyright (C) 2020-2021 Famedly GmbH                                       *
 *   Copyright (C) 2024 Jan Christian Grünhage                                  *
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
use rand_core::{CryptoRng, RngCore};

use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

use crate::{
    helper::{hex_pair_to_bytes, leading_ones, strip_ones},
    FromHexError,
};

/// Represents a node in the yggdrasil network.
///
/// The keys in here are as used in the reference implementation [yggdrasil-go]. In a previous
/// version of this crate, it was based on the [YS001: Yggdrasil Core Specification], but that spec
/// has not been updated for the new v0.4 release of yggdrasil-go release yet, so for compatibility
/// with the new version, we're basing this on the reference implementation instead.
///
/// [yggdrasil-go]: https://github.com/yggdrasil-network/yggdrasil-go
/// [YS001: Yggdrasil Core Specification]: https://github.com/yggdrasil-network/yggdrasil-specs/blob/ys001/ys001-yggdrasil-core-specification.md
pub struct NodeIdentity {
    /// ed25519 key pair, used as the node identity and for address generation
    pub signing_keys: ed25519_dalek::Keypair,
}

impl NodeIdentity {
    const ADDR_BYTE: u8 = 0xfeu8;
    const SNET_BYTE: u8 = 0x01u8;
    /// This prefix is taken from [yggdrasil-go](yggdrasil-go),
    /// it's the one currently used in the yggdrasil network,
    /// namely `200::/7`.
    ///
    /// [yggdrasil-go]: https://github.com/yggdrasil-network/yggdrasil-go
    pub const IP_PREFIX: [u8; 1] = [0x02u8];

    /// Generates node identity using the supplied CSPRNG
    ///
    /// ```rust
    /// use rand::thread_rng;
    /// use std::net::Ipv6Addr;
    /// use yggdrasil_keys::NodeIdentity;
    ///
    /// let node = NodeIdentity::new(&mut thread_rng());
    /// let address : Ipv6Addr = node.into();
    /// ```
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let signing_keys = ed25519_dalek::Keypair::generate(csprng);
        Self { signing_keys }
    }

    /// Parses hexadecimally encoded keypairs.
    ///
    /// Arguments:
    ///  * `sec_hex`: Either 32 hex encoded bytes for the secret key,
    ///  or 64 hex encoded bytes for the keypair
    ///  * `pub_hex`: Optionally, 32 hex encoded bytes for the public key
    ///
    /// These arguments work like this:
    ///  - You have to supply the secret key.
    ///  - You can supply the public key, but you don't have to.
    ///  If it's missing, one will be generated from the secret key.
    ///  - If you pass a keypair to the `sec_hex` argument,
    ///  and additionally a public key to the `pub_hex` argument,
    ///  the two keys will be compared. If they differ, the function returns an error.
    pub fn from_hex(sec_hex: &str, pub_hex: Option<&str>) -> Result<Self, FromHexError> {
        let (secret, public) = hex_pair_to_bytes(sec_hex, pub_hex)?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&secret)?;
        let public = match public {
            Some(public) => ed25519_dalek::PublicKey::from_bytes(&public)?,
            None => ed25519_dalek::PublicKey::from(&secret),
        };
        Ok(Self {
            signing_keys: ed25519_dalek::Keypair { secret, public },
        })
    }

    /// Hex-encode the secret and public keys into a String each
    pub fn to_hex_split(&self) -> (String, String) {
        let secret_bytes = self.signing_keys.secret.as_bytes();
        let public_bytes = self.signing_keys.public.as_bytes();
        (hex::encode(secret_bytes), hex::encode(public_bytes))
    }

    /// Hex-encode the keypair into a combined String
    pub fn to_hex_joined(&self) -> String {
        let (secret, public) = self.to_hex_split();
        format!("{}{}", secret, public)
    }

    /// The "strength" of a given NodeIdentity is the number of leading one bits set in the
    /// inverted public key.
    pub fn strength(&self) -> u32 {
        leading_ones(self.inverted_pub_key())
    }

    /// Calculate the address for this NodeIdentity with the given IP prefix.
    pub fn address_with_prefix(&self, prefix: &[u8]) -> Ipv6Addr {
        Ipv6Addr::from(self.address_bytes(prefix, false))
    }

    /// Calculate the `/64` subnet for this NodeIdentity with the given IP prefix.
    pub fn subnet_with_prefix(&self, prefix: &[u8]) -> Ipv6Net {
        let addr = Ipv6Addr::from(self.address_bytes(prefix, true));
        Ipv6Net::new(addr, 64).unwrap().trunc()
    }

    /// Clone and invert public key
    fn inverted_pub_key(&self) -> [u8; 32] {
        let mut inverse_public = *self.signing_keys.public.as_bytes();
        for byte in inverse_public.iter_mut() {
            *byte = !*byte;
        }
        inverse_public
    }

    /// Calculate the address bytes.
    fn address_bytes(&self, prefix: &[u8], net: bool) -> [u8; 16] {
        // Prefix must be at most a /48 for subnets or /112 for addresses
        assert!(prefix.len() <= if net { 6 } else { 14 });

        // Create 16 bytes array and copy the prefix into it
        let mut bytes: [u8; 16] = [0u8; 16];
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
        let (ones, remainder) = strip_ones(self.inverted_pub_key());

        // Set the next byte to the the number of ones stripped from the Node ID
        bytes[prefix.len()] = ones as u8;

        // Set the remaining bytes until the end of the address/subnet
        // to the remainder of the Node ID
        let end = if net { 8 } else { 16 };
        bytes[(prefix.len() + 1)..end].copy_from_slice(&remainder[0..(end - (prefix.len() + 1))]);

        // Return the address bytes
        bytes
    }

    /// Calculate the address for this NodeIdentity with the default IP prefix.
    pub fn address(&self) -> Ipv6Addr {
        self.address_with_prefix(&Self::IP_PREFIX)
    }

    /// Calculate the `/64` subnet for this NodeIdentity with the default IP prefix.
    pub fn subnet(&self) -> Ipv6Net {
        self.subnet_with_prefix(&Self::IP_PREFIX)
    }
}

impl From<NodeIdentity> for Ipv6Addr {
    fn from(identity: NodeIdentity) -> Ipv6Addr {
        identity.address()
    }
}

impl From<NodeIdentity> for Ipv6Net {
    fn from(identity: NodeIdentity) -> Ipv6Net {
        identity.subnet()
    }
}
