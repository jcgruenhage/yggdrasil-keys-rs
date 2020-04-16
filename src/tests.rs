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
