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
use generic_array::{typenum::consts::U64, GenericArray};
use std::convert::TryInto;

use crate::FromHexError;

/// count the leading ones on sha512 hash
pub(crate) fn leading_ones(sha512: &GenericArray<u8, U64>) -> u32 {
    const INVERTER: u8 = 255u8;
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

/// count the leading ones on a sha512 hash,
/// strip them plus the following zero off,
/// return the count and the remainder.
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

/// Get one or two 32 byte arrays out of one or two strings
///
/// You probably want to look at [`crate::NodeIdentity::from_hex`]
///
/// `secret` is either two 32 byte hex encoded values concatenated
/// ("secret" + "public") or just one 32 byte hex encoded value ("secret").
///
/// public is optionally a 32 byte hex encoded value ("public").
///
/// If 32 bytes are passed to both, two byte arrays of length 32 are returned.
///
/// If 64 + 32 bytes are passed, two byte arrays of length 32 will be returned,
/// and the two public parts will be compared.
///
/// If 32 bytes are passed as secret, and `None` as public,
/// one byte array of length 32 will be returned.
///
/// If anything else is passed, an error will be returned.
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
