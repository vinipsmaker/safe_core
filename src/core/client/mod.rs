// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Lazy evaluated response getter.
pub mod response_getter;

mod user_account;
mod message_queue;

#[cfg(feature = "use-mock-routing")]
mod non_networking_test_framework;

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, mpsc};

use self::user_account::Account;
use self::message_queue::MessageQueue;
use self::response_getter::{GetResponseGetter, MutationResponseGetter};

use core::utility;
use core::errors::CoreError;
use core::translated_events::NetworkEvent;

use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::serialise;
use safe_network_common::TYPE_TAG_SESSION_PACKET;
use safe_network_common::messaging::{MpidMessage, MpidMessageWrapper};
use routing::{Authority, Data, DataIdentifier, FullId, MessageId, PlainData, StructuredData,
              XorName};

use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::crypto::hash::sha256;

#[cfg(feature = "use-mock-routing")]
use self::non_networking_test_framework::RoutingMock as Routing;
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;

const LOGIC_ERROR: &'static str = "Logic Error !! Report as bug.";

/// The main self-authentication client instance that will interface all the request from high
/// level API's to the actual routing layer and manage all interactions with it. This is
/// essentially a non-blocking Client with upper layers having an option to either block and wait
/// on the returned ResponseGetters for receiving network response or spawn a new thread. The Client
/// itself is however well equipped for parallel and non-blocking PUTs and GETS.
pub struct Client {
    account: Option<Account>,
    routing: Routing,
    _raii_joiner: RaiiThreadJoiner,
    message_queue: Arc<Mutex<MessageQueue>>,
    session_packet_id: Option<XorName>,
    session_packet_keys: Option<SessionPacketEncryptionKeys>,
    client_manager_addr: Option<XorName>,
}

impl Client {
    /// This is a getter-only Gateway function to the Maidsafe network. It will create an
    /// unregistered random clinet, which can do very limited set of operations - eg., a
    /// Network-Get
    pub fn create_unregistered_client() -> Result<Client, CoreError> {
        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let routing = try!(Routing::new(routing_sender, None));
        let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                             vec![network_event_sender]);

        match try!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            _ => return Err(CoreError::OperationAborted),
        }

        Ok(Client {
            account: None,
            routing: routing,
            _raii_joiner: raii_joiner,
            message_queue: message_queue,
            session_packet_id: None,
            session_packet_keys: None,
            client_manager_addr: None,
        })
    }

    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// log_in. This will help create a fresh account for the user in the SAFE-network.
    pub fn create_account(keyword: String,
                          pin: String,
                          password: String)
                          -> Result<Client, CoreError> {
        let account_packet = Account::new(None, None);
        let id_packet = FullId::with_keys((account_packet.get_maid().public_keys().1.clone(),
                                           account_packet.get_maid().secret_keys().1.clone()),
                                          (account_packet.get_maid().public_keys().0.clone(),
                                           account_packet.get_maid().secret_keys().0.clone()));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let routing = try!(Routing::new(routing_sender, Some(id_packet)));
        let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                             vec![network_event_sender]);

        match try!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            _ => return Err(CoreError::OperationAborted),
        }

        let hash_sign_key = sha256::hash(&(account_packet.get_maid().public_keys().0).0);
        let client_manager_addr = XorName(hash_sign_key.0);

        let client = Client {
            account: Some(account_packet),
            routing: routing,
            _raii_joiner: raii_joiner,
            message_queue: message_queue,
            session_packet_id: Some(try!(Account::generate_network_id(keyword.as_bytes(),
                                                                      pin.as_bytes()))),
            session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
            client_manager_addr: Some(client_manager_addr),
        };

        {
            let account = unwrap_option!(client.account.as_ref(), LOGIC_ERROR);
            let session_packet_keys = unwrap_option!(client.session_packet_keys.as_ref(),
                                                     LOGIC_ERROR);

            let session_packet_id = unwrap_option!(client.session_packet_id.as_ref(), LOGIC_ERROR)
                .clone();
            let account_version = try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                         session_packet_id,
                                         0,
                                         try!(account.encrypt(session_packet_keys.get_password(),
                                                      session_packet_keys.get_pin())),
                                         vec![account.get_public_maid().public_keys().0.clone()],
                                         Vec::new(),
                                         Some(&account.get_maid().secret_keys().0)));

            try!(try!(client.put(Data::Structured(account_version), None)).get());
        }

        Ok(client)
    }

    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// create_account. This will help log into an already created account for the user in the
    /// SAFE-network.
    pub fn log_in(keyword: String, pin: String, password: String) -> Result<Client, CoreError> {
        let mut unregistered_client = try!(Client::create_unregistered_client());
        let user_id = try!(Account::generate_network_id(keyword.as_bytes(), pin.as_bytes()));

        let session_packet_request = DataIdentifier::Structured(user_id.clone(),
                                                                TYPE_TAG_SESSION_PACKET);

        let resp_getter = try!(unregistered_client.get(session_packet_request, None));

        if let Data::Structured(session_packet) = try!(resp_getter.get()) {
            let decrypted_session_packet = try!(Account::decrypt(session_packet.get_data(),
                                                                 password.as_bytes(),
                                                                 pin.as_bytes()));
            let id_packet = FullId::with_keys((decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .1
                                                  .clone(),
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .1
                                                  .clone()),
                                              (decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .0
                                                  .clone(),
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .0
                                                  .clone()));

            let (routing_sender, routing_receiver) = mpsc::channel();
            let (network_event_sender, network_event_receiver) = mpsc::channel();

            let routing = try!(Routing::new(routing_sender, Some(id_packet)));
            let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                                 vec![network_event_sender]);

            match try!(network_event_receiver.recv()) {
                NetworkEvent::Connected => (),
                _ => return Err(CoreError::OperationAborted),
            }

            let hash_sign_key = sha256::hash(&(decrypted_session_packet.get_maid()
                    .public_keys()
                    .0)
                .0);
            let client_manager_addr = XorName(hash_sign_key.0);

            let client = Client {
                account: Some(decrypted_session_packet),
                routing: routing,
                _raii_joiner: raii_joiner,
                message_queue: message_queue,
                session_packet_id: Some(try!(Account::generate_network_id(keyword.as_bytes(),
                                                                          pin.as_bytes()))),
                session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
                client_manager_addr: Some(client_manager_addr),
            };

            Ok(client)
        } else {
            Err(CoreError::ReceivedUnexpectedData)
        }
    }

    /// Create an entry for the Root Directory ID for the user into the session packet, encrypt and
    /// store it. It will be retrieved when the user logs into their account. Root directory ID is
    /// necessary to fetch all of the user's data as all further data is encoded as meta-information
    /// into the Root Directory or one of its subdirectories.
    pub fn set_user_root_directory_id(&mut self, root_dir_id: XorName) -> Result<(), CoreError> {
        if try!(self.account.as_mut().ok_or(CoreError::OperationForbiddenForClient))
            .set_user_root_dir_id(root_dir_id) {
            self.update_session_packet()
        } else {
            Err(CoreError::RootDirectoryAlreadyExists)
        }
    }

    /// Get User's Root Directory ID if available in session packet used for current login
    pub fn get_user_root_directory_id(&self) -> Option<&XorName> {
        self.account.as_ref().and_then(|account| account.get_user_root_dir_id())
    }

    /// Create an entry for the Maidsafe configuration specific Root Directory ID into the
    /// session packet, encrypt and store it. It will be retrieved when the user logs into
    /// their account. Root directory ID is necessary to fetch all of configuration data as all
    /// further data is encoded as meta-information into the config Root Directory or one of its
    /// subdirectories.
    pub fn set_configuration_root_directory_id(&mut self,
                                               root_dir_id: XorName)
                                               -> Result<(), CoreError> {
        if try!(self.account.as_mut().ok_or(CoreError::OperationForbiddenForClient))
            .set_maidsafe_config_root_dir_id(root_dir_id) {
            self.update_session_packet()
        } else {
            Err(CoreError::RootDirectoryAlreadyExists)
        }
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in session packet used
    /// for current login
    pub fn get_configuration_root_directory_id(&self) -> Option<&XorName> {
        self.account.as_ref().and_then(|account| account.get_maidsafe_config_root_dir_id())
    }

    /// Combined Asymmetric and Symmetric encryption. The data is encrypted using random Key and
    /// IV with Xsalsa-symmetric encryption. Random IV ensures that same plain text produces
    /// different cipher-texts for each fresh symmetric encryption. The Key and IV are then
    /// asymmetrically encrypted using Public-MAID and the whole thing is then serialised into a
    /// single `Vec<u8>`.
    pub fn hybrid_encrypt(&self,
                          data_to_encrypt: &[u8],
                          nonce_opt: Option<&box_::Nonce>)
                          -> Result<Vec<u8>, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));

        let mut nonce_default = box_::Nonce([0u8; box_::NONCEBYTES]);
        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = sha256::hash(&account.get_public_maid().name().0);
                let min_length = ::std::cmp::min(box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce_default.0[it.0] = *it.1;
                }
                &nonce_default
            }
        };

        utility::hybrid_encrypt(data_to_encrypt,
                                &nonce,
                                &account.get_public_maid().public_keys().1,
                                &account.get_maid().secret_keys().1)
    }

    /// Reverse of hybrid_encrypt. Refer hybrid_encrypt.
    pub fn hybrid_decrypt(&self,
                          data_to_decrypt: &[u8],
                          nonce_opt: Option<&box_::Nonce>)
                          -> Result<Vec<u8>, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));

        let mut nonce_default = box_::Nonce([0u8; box_::NONCEBYTES]);
        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = sha256::hash(&account.get_public_maid().name().0);
                let min_length = ::std::cmp::min(box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce_default.0[it.0] = *it.1;
                }
                &nonce_default
            }
        };

        utility::hybrid_decrypt(data_to_decrypt,
                                &nonce,
                                &account.get_public_maid().public_keys().1,
                                &account.get_maid().secret_keys().1)
    }

    /// Get data from the network. This is non-blocking.
    pub fn get(&mut self,
               request_for: DataIdentifier,
               opt_dst: Option<Authority>)
               -> Result<GetResponseGetter, CoreError> {
        if let DataIdentifier::Immutable(..) = request_for {
            let mut msg_queue = unwrap_result!(self.message_queue.lock());
            if msg_queue.local_cache_check(&request_for.name()) {
                return Ok(GetResponseGetter::new(None, self.message_queue.clone(), request_for));
            }
        }

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(request_for.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap_result!(self.message_queue.lock())
            .register_response_observer(msg_id.clone(), tx.clone());

        try!(self.routing.send_get_request(dst, request_for.clone(), msg_id));

        Ok(GetResponseGetter::new(Some((tx, rx)), self.message_queue.clone(), request_for))
    }

    /// Put data onto the network. This is non-blocking.
    pub fn put(&self,
               data: Data,
               opt_dst: Option<Authority>)
               -> Result<MutationResponseGetter, CoreError> {
        let dst = match opt_dst {
            Some(auth) => auth,
            None => {
                Authority::ClientManager(try!(self.get_default_client_manager_address()).clone())
            }
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap_result!(self.message_queue.lock())
            .register_response_observer(msg_id.clone(), tx.clone());

        try!(self.routing.send_put_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// Post data onto the network
    pub fn post(&self,
                data: Data,
                opt_dst: Option<Authority>)
                -> Result<MutationResponseGetter, CoreError> {
        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(data.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap_result!(self.message_queue.lock())
            .register_response_observer(msg_id.clone(), tx.clone());

        try!(self.routing.send_post_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// Delete data from the network
    pub fn delete(&self,
                  data: Data,
                  opt_dst: Option<Authority>)
                  -> Result<MutationResponseGetter, CoreError> {
        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(data.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap_result!(self.message_queue.lock())
            .register_response_observer(msg_id.clone(), tx.clone());

        try!(self.routing.send_delete_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    // TODO Redo this since response handling is integrated - For Qi right now
    /// Send a message to receiver via the network. This is non-blocking.
    pub fn send_message(&self,
                        mpid_account: XorName,
                        msg_metadata: Vec<u8>,
                        msg_content: Vec<u8>,
                        receiver: XorName,
                        secret_key: &sign::SecretKey)
                        -> Result<MutationResponseGetter, CoreError> {
        let mpid_message = try!(MpidMessage::new(mpid_account,
                                                 msg_metadata,
                                                 receiver,
                                                 msg_content,
                                                 secret_key));
        let name = try!(mpid_message.name());
        let request = MpidMessageWrapper::PutMessage(mpid_message);

        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(name, serialised_request));

        self.put(data, Some(Authority::ClientManager(mpid_account)))
    }

    /// Delete a message from own or sender's outbox. This is non-blocking.
    pub fn delete_message(&self,
                          target_account: XorName,
                          message_name: XorName)
                          -> Result<MutationResponseGetter, CoreError> {
        self.messaging_delete_request(target_account,
                                      message_name,
                                      MpidMessageWrapper::DeleteMessage(message_name.clone()))
    }

    /// Delete a header from own inbox. This is non-blocking.
    pub fn delete_header(&self,
                         mpid_account: XorName,
                         header_name: XorName)
                         -> Result<MutationResponseGetter, CoreError> {
        self.messaging_delete_request(mpid_account,
                                      header_name,
                                      MpidMessageWrapper::DeleteHeader(header_name.clone()))
    }

    fn messaging_delete_request(&self,
                                account: XorName,
                                name: XorName,
                                request: MpidMessageWrapper)
                                -> Result<MutationResponseGetter, CoreError> {
        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(name, serialised_request));

        self.delete(data, Some(Authority::ClientManager(account)))
    }

    /// Register as an online mpid_messaging client to the network. This is non-blocking.
    pub fn register_online(&self, mpid_account: XorName) -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::Online)
    }

    /// Query the targeted messages' header that still in the outbox. This is non-blocking.
    pub fn query_outbox_headers(&self,
                                mpid_account: XorName,
                                headers: Vec<XorName>)
                                -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::OutboxHas(headers))
    }

    /// Get the list of messages' headers that still in the outbox. This is non-blocking.
    pub fn get_outbox_headers(&self,
                              mpid_account: XorName)
                              -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::GetOutboxHeaders)
    }

    // TODO - Qi to check if this is alright - Post something should not require version caching.
    // Should this not be a GET ? - Asked by Spandan
    fn messaging_post_request(&self,
                              mpid_account: XorName,
                              request: MpidMessageWrapper)
                              -> Result<GetResponseGetter, CoreError> {
        let data_request = DataIdentifier::Plain(mpid_account);

        {
            let mut msg_queue = unwrap_result!(self.message_queue.lock());
            if msg_queue.local_cache_check(&mpid_account) {
                return Ok(GetResponseGetter::new(None, self.message_queue.clone(), data_request));
            }
        }

        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(mpid_account, serialised_request));
        try!(try!(self.post(data, Some(Authority::ClientManager(mpid_account)))).get());

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap_result!(self.message_queue.lock())
            .register_response_observer(msg_id.clone(), tx.clone());

        Ok(GetResponseGetter::new(Some((tx, rx)), self.message_queue.clone(), data_request))
    }

    /// Returns the public encryption key
    pub fn get_public_encryption_key(&self) -> Result<&box_::PublicKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().public_keys().1)
    }

    /// Returns the Secret encryption key
    pub fn get_secret_encryption_key(&self) -> Result<&box_::SecretKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().secret_keys().1)
    }

    /// Returns the Public Signing key
    pub fn get_public_signing_key(&self) -> Result<&sign::PublicKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().public_keys().0)
    }

    /// Returns the Secret Signing key
    pub fn get_secret_signing_key(&self) -> Result<&sign::SecretKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().secret_keys().0)
    }

    /// Add observers for Network Events like `Connected`, `Disconnected`, `Terminated`
    pub fn add_network_event_observer(&self, sender: Sender<NetworkEvent>) {
        unwrap_result!(self.message_queue.lock()).add_network_event_observer(sender);
    }

    /// Get the default address where the PUTs will go to for this client
    pub fn get_default_client_manager_address(&self) -> Result<&XorName, CoreError> {
        self.client_manager_addr.as_ref().ok_or(CoreError::OperationForbiddenForClient)
    }

    /// Set the default address where the PUTs and DELETEs will go to for this client
    pub fn set_default_client_manager_address(&mut self,
                                              address: XorName)
                                              -> Result<(), CoreError> {
        match self.client_manager_addr.as_mut() {
            Some(contained_address) => *contained_address = address,
            None => return Err(CoreError::OperationForbiddenForClient),
        }

        Ok(())
    }

    fn update_session_packet(&mut self) -> Result<(), CoreError> {
        let session_packet_id = try!(self.session_packet_id
                .as_ref()
                .ok_or(CoreError::OperationForbiddenForClient))
            .clone();
        let session_packet_request = DataIdentifier::Structured(session_packet_id.clone(),
                                                                TYPE_TAG_SESSION_PACKET);

        let resp_getter = try!(self.get(session_packet_request, None));

        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        let session_packet_keys = try!(self.session_packet_keys
            .as_ref()
            .ok_or(CoreError::OperationForbiddenForClient));

        if let Data::Structured(retrieved_session_packet) = try!(resp_getter.get()) {
            let encrypted_account = try!(account.encrypt(session_packet_keys.get_password(),
                                                         session_packet_keys.get_pin()));

            let new_account_version = try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                         session_packet_id,
                                         retrieved_session_packet.get_version() + 1,
                                         encrypted_account,
                                         vec![account.get_public_maid()
                                                  .public_keys()
                                                  .0
                                                  .clone()],
                                         Vec::new(),
                                         Some(&account.get_maid().secret_keys().0)));
            try!(self.post(Data::Structured(new_account_version), None)).get()
        } else {
            Err(CoreError::ReceivedUnexpectedData)
        }
    }
}

/// //////////////////////////////////////////////////////////////
/// Helper Struct
/// //////////////////////////////////////////////////////////////

struct SessionPacketEncryptionKeys {
    pin: Vec<u8>,
    password: Vec<u8>,
}

impl SessionPacketEncryptionKeys {
    fn new(password: String, pin: String) -> SessionPacketEncryptionKeys {
        SessionPacketEncryptionKeys {
            pin: pin.into_bytes(),
            password: password.into_bytes(),
        }
    }

    fn get_password(&self) -> &[u8] {
        &self.password[..]
    }

    fn get_pin(&self) -> &[u8] {
        &self.pin[..]
    }
}

/// //////////////////////////////////////////////////////////////
#[cfg(test)]
mod test {
    use super::*;

    use core::utility;
    use core::errors::CoreError;
    use core::client::response_getter::GetResponseGetter;

    use rand;
    use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XOR_NAME_LEN, XorName};
    use safe_network_common::client_errors::MutationError;

    #[test]
    fn account_creation() {
        let keyword = unwrap_result!(utility::generate_random_string(10));
        let password = unwrap_result!(utility::generate_random_string(10));
        let pin = unwrap_result!(utility::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ =
            unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));

        // Account creation - same keyword, pin and password - should fail
        match Client::create_account(keyword.clone(), pin.clone(), password.clone()) {
            Ok(_) => panic!("Account name hijaking should fail !"),
            Err(CoreError::MutationFailure { reason: MutationError::AccountExists, .. }) => (),
            Err(err) => panic!("{:?}", err),
        }

        // Account creation - same keyword and pin - different password - should fail
        let new_password = unwrap_result!(utility::generate_random_string(10));
        match Client::create_account(keyword.clone(), pin.clone(), new_password) {
            Ok(_) => panic!("Account name hijaking should fail !"),
            Err(CoreError::MutationFailure { reason: MutationError::AccountExists, .. }) => (),
            Err(err) => panic!("{:?}", err),
        }

        // Account creation - same keyword and password - different pin - should succeed
        let new_pin = unwrap_result!(utility::generate_random_string(10));
        let _ = unwrap_result!(Client::create_account(keyword, new_pin, password.clone()));

        // Account creation - same pin and password - different keyword - should succeed
        let new_keyword = unwrap_result!(utility::generate_random_string(10));
        let _ = unwrap_result!(Client::create_account(new_keyword, pin, password));
    }

    #[test]
    fn account_login() {
        let keyword = unwrap_result!(utility::generate_random_string(10));
        let password = unwrap_result!(utility::generate_random_string(10));
        let pin = unwrap_result!(utility::generate_random_string(10));

        // Creation should pass
        let _ =
            unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));

        // Correct Credentials - Login Should Pass
        let _ = unwrap_result!(Client::log_in(keyword, pin, password));
    }

    #[test]
    fn unregistered_client() {
        let immut_data = ImmutableData::new(unwrap_result!(utility::generate_random_vector(30)));
        let orig_data = Data::Immutable(immut_data);

        // Registered Client PUTs something onto the network
        {
            let keyword = unwrap_result!(utility::generate_random_string(10));
            let password = unwrap_result!(utility::generate_random_string(10));
            let pin = unwrap_result!(utility::generate_random_string(10));

            // Creation should pass
            let client = unwrap_result!(Client::create_account(keyword, pin, password));
            unwrap_result!(unwrap_result!(client.put(orig_data.clone(), None)).get());
        }

        // Unregistered Client should be able to retrieve the data
        let mut unregistered_client = unwrap_result!(Client::create_unregistered_client());
        let request = DataIdentifier::Immutable(orig_data.name());
        let rxd_data = unwrap_result!(unwrap_result!(unregistered_client.get(request, None)).get());

        assert_eq!(rxd_data, orig_data);

        // Operations Not Allowed for Unregistered Client
        let rand_name: XorName = rand::random();

        match (unregistered_client.set_user_root_directory_id(rand_name.clone()),
               unregistered_client.set_configuration_root_directory_id(rand_name)) {
            (Err(CoreError::OperationForbiddenForClient),
             Err(CoreError::OperationForbiddenForClient)) => (),
            _ => panic!("Unexpected !!"),
        };
    }

    #[test]
    fn user_root_dir_id_creation() {
        // Construct Client
        let keyword = unwrap_result!(utility::generate_random_string(10));
        let password = unwrap_result!(utility::generate_random_string(10));
        let pin = unwrap_result!(utility::generate_random_string(10));

        let mut client =
            unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_none());

        let root_dir_id = XorName([99u8; XOR_NAME_LEN]);
        unwrap_result!(client.set_user_root_directory_id(root_dir_id.clone()));

        // Correct Credentials - Login Should Pass
        let client = unwrap_result!(Client::log_in(keyword, pin, password));

        assert!(client.get_user_root_directory_id().is_some());
        assert!(client.get_configuration_root_directory_id().is_none());

        assert_eq!(client.get_user_root_directory_id(), Some(&root_dir_id));
    }

    #[test]
    fn maidsafe_config_root_dir_id_creation() {
        // Construct Client
        let keyword = unwrap_result!(utility::generate_random_string(10));
        let password = unwrap_result!(utility::generate_random_string(10));
        let pin = unwrap_result!(utility::generate_random_string(10));

        let mut client =
            unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_none());

        let root_dir_id = XorName([99u8; XOR_NAME_LEN]);
        unwrap_result!(client.set_configuration_root_directory_id(root_dir_id.clone()));

        // Correct Credentials - Login Should Pass
        let client = unwrap_result!(Client::log_in(keyword, pin, password));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_some());

        assert_eq!(client.get_configuration_root_directory_id(),
                   Some(&root_dir_id));
    }

    #[test]
    fn hybrid_encryption_decryption() {
        // Construct Client
        let keyword = unwrap_result!(utility::generate_random_string(10));
        let password = unwrap_result!(utility::generate_random_string(10));
        let pin = unwrap_result!(utility::generate_random_string(10));

        let client = unwrap_result!(Client::create_account(keyword, pin, password));

        // Identical Plain Texts
        let plain_text_original_0 = vec![123u8; 1000];
        let plain_text_original_1 = plain_text_original_0.clone();

        // Encrypt passing Nonce
        let nonce = ::sodiumoxide::crypto::box_::gen_nonce();
        let cipher_text_0 =
            unwrap_result!(client.hybrid_encrypt(&plain_text_original_0[..], Some(&nonce)));
        let cipher_text_1 =
            unwrap_result!(client.hybrid_encrypt(&plain_text_original_1[..], Some(&nonce)));

        // Encrypt without passing Nonce
        let cipher_text_2 = unwrap_result!(client.hybrid_encrypt(&plain_text_original_0[..], None));
        let cipher_text_3 = unwrap_result!(client.hybrid_encrypt(&plain_text_original_1[..], None));

        // Same Plain Texts
        assert_eq!(plain_text_original_0, plain_text_original_1);

        // Different Results because of random "iv"
        assert!(cipher_text_0 != cipher_text_1);
        assert!(cipher_text_0 != cipher_text_2);
        assert!(cipher_text_0 != cipher_text_3);
        assert!(cipher_text_2 != cipher_text_1);
        assert!(cipher_text_2 != cipher_text_3);

        // Decrypt with Nonce
        let plain_text_0 = unwrap_result!(client.hybrid_decrypt(&cipher_text_0, Some(&nonce)));
        let plain_text_1 = unwrap_result!(client.hybrid_decrypt(&cipher_text_1, Some(&nonce)));

        // Decrypt without Nonce
        let plain_text_2 = unwrap_result!(client.hybrid_decrypt(&cipher_text_2, None));
        let plain_text_3 = unwrap_result!(client.hybrid_decrypt(&cipher_text_3, None));

        // Decryption without passing Nonce for something encrypted with passing Nonce - Should Fail
        match client.hybrid_decrypt(&cipher_text_0, None) {
            Ok(_) => panic!("Should have failed !"),
            Err(CoreError::AsymmetricDecipherFailure) => (),
            Err(error) => panic!("{:?}", error),
        }
        // Decryption passing Nonce for something encrypted without passing Nonce - Should Fail
        match client.hybrid_decrypt(&cipher_text_3, Some(&nonce)) {
            Ok(_) => panic!("Should have failed !"),
            Err(CoreError::AsymmetricDecipherFailure) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Should have decrypted to the same Plain Texts
        assert_eq!(plain_text_original_0, plain_text_0);
        assert_eq!(plain_text_original_1, plain_text_1);
        assert_eq!(plain_text_original_0, plain_text_2);
        assert_eq!(plain_text_original_1, plain_text_3);
    }

    #[test]
    fn version_caching() {
        let mut client = unwrap_result!(utility::test_utils::get_client());

        // Version Caching should work for ImmutableData
        {
            let immut_data =
                ImmutableData::new(unwrap_result!(utility::generate_random_vector(10)));
            let data = Data::Immutable(immut_data);

            unwrap_result!(unwrap_result!(client.put(data.clone(), None)).get());

            let data_request = DataIdentifier::Immutable(data.name());

            // Should not initially be in version cache
            {
                let resp_getter = GetResponseGetter::new(None,
                                                         client.message_queue.clone(),
                                                         data_request.clone());

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }

            let response_getter = unwrap_result!(client.get(data_request.clone(), None));
            assert_eq!(unwrap_result!(response_getter.get()), data);

            let resp_getter =
                GetResponseGetter::new(None, client.message_queue.clone(), data_request);
            assert_eq!(unwrap_result!(resp_getter.get()), data);
        }

        // Version Caching should NOT work for StructuredData
        {
            const TYPE_TAG: u64 = 15000;
            let id: XorName = rand::random();

            let struct_data = unwrap_result!(StructuredData::new(TYPE_TAG,
                                                                 id.clone(),
                                                                 0,
                                                                 Vec::new(),
                                                                 Vec::new(),
                                                                 Vec::new(),
                                                                 None));
            let data = Data::Structured(struct_data);

            unwrap_result!(unwrap_result!(client.put(data.clone(), None)).get());

            let data_request = DataIdentifier::Structured(id, TYPE_TAG);

            // Should not initially be in version cache
            {
                let resp_getter = GetResponseGetter::new(None,
                                                         client.message_queue.clone(),
                                                         data_request.clone());

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }

            let response_getter = unwrap_result!(client.get(data_request.clone(), None));
            assert_eq!(unwrap_result!(response_getter.get()), data);

            // Should not be in version cache even after fetch
            {
                let resp_getter =
                    GetResponseGetter::new(None, client.message_queue.clone(), data_request);

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }
        }
    }
}
