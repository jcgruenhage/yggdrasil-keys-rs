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

use std::net::Ipv6Addr;

const ENC_PUB_HEX: &'static str = "551e45e3e871bf843be66a9188f7e229f198e685f169ee2dface9dcd2e518661";
const ENC_SEC_HEX: &'static str = "04b3287a12837cbed0a9e235e2db1a7a300d4b7bdb63079da0e320090b898020";
#[allow(dead_code)]
const ENC_PAIR_HEX: &'static str = "04b3287a12837cbed0a9e235e2db1a7a300d4b7bdb63079da0e320090b898020551e45e3e871bf843be66a9188f7e229f198e685f169ee2dface9dcd2e518661";
const NODE_ID_HEX : &'static str = "fffff21bbdda03246ea9f855be6eeeaf1baf809dc151e0f82ffcac1be3cec5f4ce0953ddccf8b3202bf20eb96779822992710d201e07cb5721b66e9d02f54707";
const SIG_PUB_HEX: &'static str = "40a40d9fc1a8727994b54c8e416329e9f71596a97d2912be80daf5bf20da4a3d";
const SIG_SEC_HEX : &'static str = "de1f6a91c14d6e8e9a204e4926c75d4d114500a422041a8c603054dc43605e6a";
const SIG_PAIR_HEX : &'static str = "de1f6a91c14d6e8e9a204e4926c75d4d114500a422041a8c603054dc43605e6a40a40d9fc1a8727994b54c8e416329e9f71596a97d2912be80daf5bf20da4a3d";
const TREE_ID_HEX : &'static str = "ffff4252ce2cd427d22a4ead1e75fb2bfa21e193b8615c55a091a7607eb6a7d3a9c60548ca9dc2f93c64f400fe6d16d917102de0e5959d61c0e3d4e43f9cd23b";

const ADDR: Ipv6Addr = Ipv6Addr::new(
    0x0214, 0x4377, 0xbb40, 0x648d, 0xd53f, 0x0ab7, 0xcddd, 0xd5e3,
);
const SNET: Ipv6Addr = Ipv6Addr::new(
    0x0314, 0x4377, 0xbb40, 0x648d, 0x0000, 0x0000, 0x0000, 0x0000,
);

#[test]
fn test_ygg_key_parsing_and_strength() {
    // This is how the identity is stored in the config file of yggdrasil-go:
    let identity = crate::NodeIdentity::from_hex(
        SIG_PAIR_HEX,
        Some(SIG_PUB_HEX),
        ENC_SEC_HEX,
        Some(ENC_PUB_HEX),
    )
    .unwrap();

    // Validate signing keys
    assert_eq!(identity.signing_keys.to_hex_split(), (String::from(SIG_SEC_HEX), String::from(SIG_PUB_HEX)));
    assert_eq!(identity.signing_keys.to_hex_joined(), String::from(SIG_PAIR_HEX));

    // Validate encryption keys
    // These two fail, but this is not actually a problem. It comes from golangs
    // curve25519 and curve25519-dalek handling scalars a bit differently, namely
    // golang clamping the scalar before each multiplication, and rust just once during
    // key generation.
    //
    // assert_eq!(identity.encryption_keys.to_hex_split(), (String::from(ENC_SEC_HEX), String::from(ENC_PUB_HEX)));
    // assert_eq!(identity.encryption_keys.to_hex_joined(), String::from(ENC_PAIR_HEX));

    let mut scalar_bytes = hex::decode(ENC_SEC_HEX).unwrap();
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let patched_scalar = hex::encode(scalar_bytes);
    assert_eq!(identity.encryption_keys.to_hex_split(), (patched_scalar, String::from(ENC_PUB_HEX)));

    // Validate ID generation and strength measurement
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

#[test]
fn test_hex_pair_to_bytes() {
    use crate::helper::hex_pair_to_bytes;

    let secret = "0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc";
    let keypair = "0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123";
    let valid_public = "6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123";
    let invalid_public = "6663a86c1ea125dc5e98be17c98f9a0f85ca9d5f595db2012f7cc3571945c123";

    // Test that the public part comparison works and the public part is returned
    let valid_result = hex_pair_to_bytes(keypair, Some(valid_public)).unwrap();
    assert_eq!(hex::decode(secret).unwrap(), valid_result.0);
    println!("test");
    assert_eq!(hex::decode(valid_public).unwrap(), valid_result.1.unwrap());
    assert!(hex_pair_to_bytes(keypair, Some(invalid_public)).is_err());

    // Return no public part if none is given
    assert!(hex_pair_to_bytes(secret, None).unwrap().1.is_none());
}
