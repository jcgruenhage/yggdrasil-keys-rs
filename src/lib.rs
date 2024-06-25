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
#![warn(missing_docs)]

//! yggdrasil-keys
//!
//! Pure rust implementation of a subset of the key handling duties for
//! the yggdrasil mesh network.
//!
//! This crate implements:
//!  - (de)serializing keys into hex Strings
//!  - generating new keys
//!  - calculating Node and Tree IDs
//!  - converting Node IDs into IPv6 addresses and subnets

mod error;
pub(crate) mod helper;
mod keys;

#[cfg(test)]
mod tests;

pub use error::FromHexError;
pub use keys::NodeIdentity;
