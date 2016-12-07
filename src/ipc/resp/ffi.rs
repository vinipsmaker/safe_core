// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use rust_sodium::crypto::{box_, secretbox, sign};

/// Represents the needed keys to work with the data
#[repr(C)]
pub struct AppKeys {
    /// Owner signing public key
    pub owner_key: [u8; sign::PUBLICKEYBYTES],
    /// Data symmetric encryption key
    pub enc_key: [u8; secretbox::KEYBYTES],
    /// Asymmetric sign public key.
    ///
    /// This is the identity of the App in the Network.
    pub sign_pk: [u8; sign::PUBLICKEYBYTES],
    /// Asymmetric sign private key.
    pub sign_sk: [u8; sign::SECRETKEYBYTES],
    /// Asymmetric enc public key.
    pub enc_pk: [u8; box_::PUBLICKEYBYTES],
    /// Asymmetric enc private key.
    pub enc_sk: [u8; box_::SECRETKEYBYTES],
}

/// Free memory
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn app_keys_free(a: *mut AppKeys) {
    let _ = super::AppKeys::from_raw(a);
}
