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

//! REST API example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

#![allow(unused_extern_crates)]#[macro_use]
extern crate maidsafe_utilities;
extern crate time;
extern crate routing;
extern crate safe_core;

use std::sync::{Arc, Mutex};

use routing::XOR_NAME_LEN;
use safe_core::core::client::Client;
use safe_core::nfs::{self, AccessLevel};
use safe_core::nfs::errors::NfsError;
use safe_core::nfs::directory_listing::DirectoryListing;
use safe_core::nfs::file::File;
use safe_core::nfs::helper::directory_helper::DirectoryHelper;
use safe_core::nfs::helper::file_helper::FileHelper;
use safe_core::nfs::helper::writer::Mode;

fn create_account() -> Result<Client, NfsError> {
    let mut pin = String::new();
    let mut keyword = String::new();
    let mut password = String::new();

    println!("\n\tAccount Creation");
    println!("\t================");

    println!("\n------------ Enter Keyword ---------------");
    let _ = std::io::stdin().read_line(&mut keyword);

    println!("\n\n------------ Enter Password --------------");
    let _ = std::io::stdin().read_line(&mut password);

    loop {
        println!("\n\n--------- Enter PIN (4 Digits) -----------");
        let _ = std::io::stdin().read_line(&mut pin);
        pin = pin.trim().to_string();
        if pin.parse::<u16>().is_ok() && pin.len() == 4 {
            break;
        }
        println!("ERROR: PIN is not 4 Digits !!");
        pin.clear();
    }

    // Account Creation
    println!("\nTrying to create an account ...");
    let _ = unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));
    println!("Account Created Successfully !!");
    println!("\n\n\tAuto Account Login");
    println!("\t==================");

    // Log into the created account
    println!("\nTrying to log into the created account using supplied credentials ...");
    let client = try!(Client::log_in(keyword, pin, password));
    println!("Account Login Successful !!");
    Ok(client)
}

fn get_root_directory(client: Arc<Mutex<Client>>) -> Result<DirectoryListing, NfsError> {
    let directory_helper = DirectoryHelper::new(client.clone());
    directory_helper.get_user_root_directory_listing()
}

fn get_user_string(placeholder: &str) -> String {
    let mut txt = String::new();
    println!("------Enter {}--------", placeholder);
    let _ = std::io::stdin().read_line(&mut txt);
    while txt.is_empty() {
        println!("{} can not be empty", placeholder);
        println!("------Enter Directory name--------");
        let _ = std::io::stdin().read_line(&mut txt);
    }
    txt
}

fn format_version_id(version_id: &[u8; XOR_NAME_LEN]) -> String {
    let mut version = String::new();
    for j in 0..4 {
        version.push_str(&version_id[j].to_string()[..]);
    }
    version.push_str("..");
    for j in (XOR_NAME_LEN - 4)..XOR_NAME_LEN {
        version.push_str(&version_id[j].to_string()[..]);
    }
    version
}

fn get_child_directory(client: Arc<Mutex<Client>>,
                       directory: &mut DirectoryListing)
                       -> Result<DirectoryListing, NfsError> {
    let ref directory_name = get_user_string("Directory name");
    let directory_metadata = try!(directory.find_sub_directory(directory_name)
        .ok_or(NfsError::DirectoryNotFound));
    let directory_helper = DirectoryHelper::new(client);

    directory_helper.get(directory_metadata.get_key())
}

fn directory_operation(option: u32,
                       client: Arc<Mutex<Client>>,
                       mut directory: &mut DirectoryListing)
                       -> Result<(), NfsError> {
    match option {
        1 => {
            // Create directory
            println!("----------Select the Directory type-----------");
            println!("1. Versioned Private Directory");
            println!("2. Versioned Public Directory");
            println!("3. UnVersioned Private Directory");
            println!("4. UnVersioned Public Directory");
            match get_user_string("number corresponding to the type").trim().parse::<usize>() {
                Ok(index) => {
                    if index > 4 {
                        println!("Invalid input");
                        return Ok(());
                    }
                    let name = get_user_string("Directory name");
                    let versioned = match index {
                        1 | 2 => true,
                        3 | 4 => false,
                        _ => true,
                    };
                    let access_level = match index {
                        1 | 3 => AccessLevel::Private,
                        2 | 4 => AccessLevel::Public,
                        _ => AccessLevel::Private,
                    };

                    if name.is_empty() {
                        return Err(NfsError::ParameterIsNotValid);
                    }

                    let tag_type = if versioned {
                        nfs::VERSIONED_DIRECTORY_LISTING_TAG
                    } else {
                        nfs::UNVERSIONED_DIRECTORY_LISTING_TAG
                    };

                    let directory_helper = DirectoryHelper::new(client.clone());
                    let _ = try!(directory_helper.create(name.clone(),
                                                         tag_type,
                                                         vec![],
                                                         versioned,
                                                         access_level,
                                                         Some(&mut directory)));
                    println!("Created Directory - {}", name);
                }
                Err(_) => println!("Invalid input"),
            };
        }
        2 => {
            // List directories
            let directory_metadata = directory.get_sub_directories();
            if directory_metadata.is_empty() {
                println!("No directories found");
            } else {
                println!("List of directories");
                println!("\t        Created On                  Name ");
                println!("\t =========================       ==========");
                for metatata in directory_metadata {
                    println!("\t {:?} \t {}",
                             time::strftime("%d-%m-%Y %H:%M UTC", &metatata.get_created_time())
                                 .unwrap(),
                             metatata.get_name());
                }
            }
        }
        3 => {
            // List versions
            let directory = try!(get_child_directory(client.clone(), directory));
            let directory_helper = DirectoryHelper::new(client.clone());
            let versions = try!(directory_helper.get_versions(directory.get_key().get_id(),
                                                              directory.get_key().get_type_tag()));
            if versions.is_empty() {
                println!("No directory versions found");
            } else {
                println!("List of directory versions");
                println!("\t No. \t Version Id");
                println!("\t === \t ==========");
                for i in 0..versions.len() {
                    println!("\t {} \t {:?}", i + 1, format_version_id(&versions[i].0));
                }
            }
        }
        4 => {
            // Delete directory
            let directory_helper = DirectoryHelper::new(client.clone());
            let _ =
                try!(directory_helper.delete(&mut directory, &get_user_string("Directory name")));
            println!("Directory deleted");
        }
        _ => {}
    };
    Ok(())
}

fn file_operation(option: u32,
                  client: Arc<Mutex<Client>>,
                  directory: &mut DirectoryListing)
                  -> Result<(), NfsError> {
    match option {
        5 => {
            // List files
            let directory = try!(get_child_directory(client, directory));
            let files: Vec<File> = directory.get_files().clone();
            if files.is_empty() {
                println!("No Files found in Directory - {}",
                         directory.get_metadata().get_name());
            } else {
                println!("List of Files");
                println!("\t        Modified On                Name ");
                println!("\t =========================      ===========");
                for file in files {
                    println!("\t {:?} \t {}",
                             time::strftime("%d-%m-%Y %H:%M UTC",
                                            &file.get_metadata().get_modified_time())
                                 .unwrap(),
                             file.get_name());
                }
            }
        }
        6 => {
            // Create file
            let directory = try!(get_child_directory(client.clone(), directory));
            let data = get_user_string("text to be saved as a file").into_bytes();
            let mut file_helper = FileHelper::new(client);
            let mut writer =
                try!(file_helper.create(get_user_string("File name"), vec![], directory));

            try!(writer.write(&data[..], 0));
            let _ = try!(writer.close());
            println!("File created");
        }
        7 => {
            // Update file
            let directory = try!(get_child_directory(client.clone(), directory));
            let file = if let Some(file) = directory.find_file(&get_user_string("File name")) {
                file
            } else {
                return Err(NfsError::FileNotFound);
            };
            let data = get_user_string("text to be saved as a file").into_bytes();
            let mut file_helper = FileHelper::new(client);
            let mut writer =
                try!(file_helper.update_content(file.clone(), Mode::Overwrite, directory.clone()));
            try!(writer.write(&data[..], 0));
            let _ = try!(writer.close());
            println!("File Updated");
        }
        8 => {
            // Read file
            let directory = try!(get_child_directory(client.clone(), directory));
            let file = if let Some(file) = directory.find_file(&get_user_string("File name")) {
                file
            } else {
                return Err(NfsError::FileNotFound);
            };
            let mut file_helper = FileHelper::new(client);
            let mut reader = try!(file_helper.read(file));
            let data_read = try!(reader.read(0, file.get_metadata().get_size()));

            match String::from_utf8(data_read) {
                Ok(data) => {
                    println!("Content Read: ");
                    println!("{}\n", data);
                }
                Err(msg) => println!("Failed: {:?}", msg),
            }
        }
        9 => {
            // Read file by version
            let directory = try!(get_child_directory(client.clone(), directory));
            let file_name = get_user_string("File name");
            let file = try!(directory.find_file(&file_name).ok_or(NfsError::FileNotFound));
            let mut file_helper = FileHelper::new(client);
            let versions = try!(file_helper.get_versions(&file, &directory));
            let ref file_version;
            if versions.len() == 1 {
                file_version = &versions[0];
            } else {
                println!("Available Versions::");
                for i in 0..versions.len() {
                    println!("\t{} Modified at {:?}",
                             i + 1,
                             time::strftime("%d-%m-%Y %H:%M UTC",
                                            &versions[i].get_metadata().get_modified_time())
                                 .unwrap())
                }
                match get_user_string("Number corresponding to the version")
                    .trim()
                    .parse::<usize>() {
                    Ok(index) => file_version = &versions[index - 1],
                    Err(_) => {
                        println!("Invalid input : Fetching latest version");
                        file_version = &versions[0];
                    }
                }
            }

            let mut reader = try!(file_helper.read(file_version));
            let data_read = try!(reader.read(0, file_version.get_metadata().get_size()));

            match String::from_utf8(data_read) {
                Ok(data) => {
                    println!("Content Read: ");
                    println!("{}\n", data);
                }
                Err(msg) => println!("Failed: {:?}", msg),
            }
        }
        10 => {
            // Delete file
            let mut directory = try!(get_child_directory(client.clone(), directory));
            let file_helper = FileHelper::new(client);
            let _ = try!(file_helper.delete(get_user_string("File name"), &mut directory));
            println!("File deleted");
        }
        11 => {
            // Copy file
            let from_directory = try!(get_child_directory(client.clone(), directory));
            let to_dir_name = get_user_string("Select the Directory to copy file to (Destination \
                                               Directory)");
            let directory_metadata = directory.get_sub_directories();

            if directory_metadata.is_empty() || directory_metadata.len() == 1 {
                println!("No directories found");
                return Ok(());
            } else {
                match directory_metadata.iter()
                    .find(|metadata| *metadata.get_name() == to_dir_name) {
                    Some(to_dir) => {
                        if from_directory.get_key() == to_dir.get_key() {
                            return Err(NfsError::DestinationAndSourceAreSame);
                        }
                        let file_name = &get_user_string("File name");
                        let file = try!(from_directory.find_file(file_name)
                            .ok_or(NfsError::FileNotFound));
                        let directory_helper = DirectoryHelper::new(client);
                        let mut destination = try!(directory_helper.get(to_dir.get_key()));
                        if destination.find_file(file_name).is_some() {
                            return Err(NfsError::FileAlreadyExistsWithSameName);
                        }
                        destination.get_mut_files().push(file.clone());
                        let _ = try!(directory_helper.update(&destination));
                        println!("File copied");
                    }
                    None => println!("Destination Directory not found"),
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn main() {
    let test_client = unwrap_result!(create_account());
    let client = Arc::new(Mutex::new(test_client));
    println!("\n\t-- Preparing storage ----\n");
    let mut root_directory = unwrap_result!(get_root_directory(client.clone()));
    println!("\n\n------  (Tip) Start by creating a directory and then store file, modify file \
              within the directory --------------------");
    loop {
        let mut option = String::new();
        {
            println!("\n----------Choose an Operation----------------");
            println!("1. Create Directory");
            println!("2. List Directories");
            println!("3. List Directory Versions");
            println!("4. Delete Directory");
            println!("5. List Files from directory");
            println!("6. Create File");
            println!("7. Update File");
            println!("8. Get file content");
            println!("9. Get file content by version");
            println!("10. Delete file");
            println!("11. Copy file");
            println!("12. Exit");
            println!("------ Enter a number --------------------");
            let _ = std::io::stdin().read_line(&mut option);
            println!("\n");
            match option.trim().parse::<u32>() {
                Ok(selection) => {
                    match selection {
                        1...4 => {
                            match directory_operation(selection,
                                                      client.clone(),
                                                      &mut root_directory) {
                                Err(msg) => println!("Failed: {:?}", msg),
                                Ok(_) => (),
                            }
                        }
                        5...11 => {
                            match file_operation(selection, client.clone(), &mut root_directory) {
                                Err(msg) => println!("Failed: {:?}", msg),
                                Ok(_) => (),
                            }
                        }
                        12 => break,
                        _ => println!("Invalid option"),
                    }
                }
                Err(_) => println!("Enter a valid number"),
            }
        }
    }
}
