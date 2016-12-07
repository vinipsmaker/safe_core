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

use routing::XorName;
use rust_sodium::crypto::{box_, secretbox, sign};

/// Ffi module
pub mod ffi;

pub use self::req::{AppExchangeInfo, AuthReq, ContainerPermission, ContainersReq, IpcReq};

/// Errors module
mod errors;
/// Request module
pub mod req;

pub use self::errors::IpcError;

// TODO: replace with `crust::Config`
/// Placeholder for `crust::Config`
#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct Config;

/// Represents the needed keys to work with the data
#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct AppKeys {
    /// Owner signing public key.
    pub owner_key: sign::PublicKey,
    /// Data symmetric encryption key
    pub enc_key: secretbox::Key,
    /// Asymmetric sign public key.
    ///
    /// This is the identity of the App in the Network.
    pub sign_pk: sign::PublicKey,
    /// Asymmetric sign private key.
    pub sign_sk: sign::SecretKey,
    /// Asymmetric enc public key.
    pub enc_pk: box_::PublicKey,
    /// Asymmetric enc private key.
    pub enc_sk: box_::SecretKey,
}

impl AppKeys {
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_raw(self) -> *mut ffi::AppKeys {
        let AppKeys { owner_key, enc_key, sign_pk, sign_sk, enc_pk, enc_sk } = self;
        Box::into_raw(Box::new(ffi::AppKeys {
            owner_key: owner_key.0,
            enc_key: enc_key.0,
            sign_pk: sign_pk.0,
            sign_sk: sign_sk.0,
            enc_pk: enc_pk.0,
            enc_sk: enc_sk.0,
        }))
    }

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(raw: *mut ffi::AppKeys) -> Self {
        let raw = Box::from_raw(raw);
        AppKeys {
            owner_key: sign::PublicKey(raw.owner_key),
            enc_key: secretbox::Key(raw.enc_key),
            sign_pk: sign::PublicKey(raw.sign_pk),
            sign_sk: sign::SecretKey(raw.sign_sk),
            enc_pk: box_::PublicKey(raw.enc_pk),
            enc_sk: box_::SecretKey(raw.enc_sk),
        }
    }
}

/// It represents the authentication response.
#[derive(RustcEncodable, RustcDecodable, Debug, PartialEq, Eq)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,
    /// The crust config.
    ///
    /// Useful to reuse bootstrap nodes and speed up access.
    pub bootstrap_config: Config,
    /// Access container
    pub access_container: Option<(XorName, u64, secretbox::Nonce)>,
}

/// Containers response
#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct ContainersGranted;

#[derive(RustcEncodable, RustcDecodable, Debug)]
/// IPC message
pub enum IpcMsg {
    /// Request
    Req {
        /// Application ID
        app_id: String,
        /// Request ID
        req_id: u32,
        /// Request
        req: IpcReq,
    },
    /// Response
    Resp {
        /// Request ID
        req_id: u32,
        /// Response
        resp: IpcResp,
    },
    /// Revoked
    Revoked {
        /// Application ID
        app_id: String,
    },
    /// Generic error like couldn't parse IpcMsg etc.
    Err(IpcError),
}

#[derive(Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
/// IPC response
// TODO: `TransOwnership` variant
pub enum IpcResp {
    /// Authentication
    Auth(Result<AuthGranted, IpcError>),
    /// Containers
    Containers(Result<ContainersGranted, IpcError>),
}
