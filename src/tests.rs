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

use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

#[allow(dead_code)]
const PUB_HEX: &'static str = "00000305eb7f19cb4506f937494ea2ebcf58e346604c0cf76be5f67271fd9a97";
const SEC_HEX: &'static str = "c752e88db1771790f6476bfd39b7f5664e4e02818455b8e9657ff063061e3049";
const PAIR_HEX : &'static str = "c752e88db1771790f6476bfd39b7f5664e4e02818455b8e9657ff063061e304900000305eb7f19cb4506f937494ea2ebcf58e346604c0cf76be5f67271fd9a97";

const ADDR: Ipv6Addr = Ipv6Addr::new(
    0x0216, 0x7d0a, 0x4073, 0x1a5d, 0x7c83, 0x645b, 0x58ae, 0x8a18,
);
const SNET: Ipv6Addr = Ipv6Addr::new(
    0x0316, 0x7d0a, 0x4073, 0x1a5d, 0x7c83, 0x645b, 0x58ae, 0x8a18,
);
const SNET_PREFIX: u8 = 64;

#[test]
fn test_ygg_key_parsing_and_strength() {
    // This is how the identity is stored in the config file of yggdrasil-go:
    let identity = crate::NodeIdentity::from_hex(PAIR_HEX, Some(PUB_HEX)).unwrap();

    // But this should give us the same result:
    let other_identity = crate::NodeIdentity::from_hex(PAIR_HEX, None).unwrap();
    assert_eq!(identity.to_hex_joined(), other_identity.to_hex_joined());

    // As should this:
    let other_identity = crate::NodeIdentity::from_hex(SEC_HEX, Some(PUB_HEX)).unwrap();
    assert_eq!(identity.to_hex_joined(), other_identity.to_hex_joined());

    // Validate signing keys
    assert_eq!(
        identity.to_hex_split(),
        (String::from(SEC_HEX), String::from(PUB_HEX))
    );
    assert_eq!(identity.to_hex_joined(), String::from(PAIR_HEX));

    // Validate ID generation and strength measurement
    assert_eq!(identity.strength(), 22);
}

#[test]
fn test_ygg_addr_generation() {
    let identity = crate::NodeIdentity::from_hex(SEC_HEX, Some(PUB_HEX)).unwrap();
    assert_eq!(Ipv6Addr::from(identity), ADDR);
    let identity = crate::NodeIdentity::from_hex(SEC_HEX, Some(PUB_HEX)).unwrap();
    assert_eq!(
        Ipv6Net::from(identity),
        Ipv6Net::new(SNET, SNET_PREFIX).unwrap().trunc()
    );
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

#[test]
fn test_shifting_and_strip_leading_ones() {
    use crate::helper::strip_ones;

    assert_eq!(
        (0, vec![0b00000000, 0b00000000]),
        strip_ones([0b00000000, 0b00000000])
    );
    assert_eq!(
        (0, vec![0b00100000, 0b00000000]),
        strip_ones([0b00010000, 0b00000000])
    );
    assert_eq!(
        (1, vec![0b00000000, 0b00000000]),
        strip_ones([0b10000000, 0b00000000])
    );
    assert_eq!((8, vec![0b00100000]), strip_ones([0b11111111, 0b00010000]));
}
