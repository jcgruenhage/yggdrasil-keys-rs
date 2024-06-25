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

use thiserror::Error;

/// Describe error for trying to decode yggdrasil keys from hex strings.
#[derive(Error, Debug)]
pub enum FromHexError {
    /// The `sec_hex` parameters can be either 64 hex encoded bytes,
    /// if they are a keypair,
    /// or 32 hex encoded bytes if they are just the private key.
    /// The `pub_hex` parameters have to be 32 hex encoded bytes.
    #[error("key has wrong length")]
    WrongKeyLength,
    /// The strings have to be valid hex.
    #[error("string is not valid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// If `pub_hex` is `Some` and `sec_hex` contains a keypair,
    /// both supplied public keys have to be the same.
    #[error("pub keys in optional argument and included with secret key differ")]
    ConflictingPubKeys,
    /// The signing keys are checked by the ed25519 implementation after parsing.
    /// If something doesn't add up, this error will be returned.
    #[error("the signature keys are invalid: {0}")]
    InvalidSigKey(#[from] ed25519_dalek::SignatureError),
}
