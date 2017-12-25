#![allow(dead_code)]
extern crate openssl;
use openssl::symm;
use encoded_string;
use encoded_string::*;
use crypt_util::*;
use crypt_algo::*;
use crypt_break::*;

pub fn set2_challenge10()
{
    let crypt = encoded_string::encoded_string_from_file("data/s2c10.txt", encoded_string::EncodingType::Base64).unwrap(); 

    let plain = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Ascii,
        val : "YELLOW SUBMARINE".to_string() 
    };
    // what are trait bounds and why does encr not satisfy them?  
    let encr = create_ecb_aes_closure(true);
    let decr = create_ecb_aes_closure(false);
    
    let mut iv : Vec<u8> = Vec::with_capacity(16);
    iv.resize(16,0);
    //create a CBC_Mode structure using those two closures and an IV of all ascii 0s blocksize of
    //16
    let mut cbc = CBC_Mode::new(encr , decr, 16, &iv);

    //call decrypt method
    let res = encoded_string::encoded_string_from_bytes(&cbc.decrypt(&crypt.get_bytes().expect(""), &plain.get_bytes().expect("")).expect(""), EncodingType::Ascii).expect("");
    println!("Challenge 10 {:?}\n", res.get_val());
}

pub fn set2_challenge11()
{
        let num_test = 1;
        let block_size = 16;
        let mut num_bad = 0;
        #[allow(unused_variables)]
        for i in 0..num_test {
            let mut was_ecb = BlockMode::INVALID;
            let mode : BlockMode;

            // create enclosing scope so that closure can expire
            // after its used in detect_block_mode thereby releasing mut borrow of was_ecb
            // The two closures here are 
            // - encr - encrypts using aes_128_ecb
            // - mod_encr - uses the oracle function to encrypt (chooses ECB half the time and CBC
            //              half.  mod_encr passes out which mode was used into was_ecb
            {
                //let encr = create_ecb_aes_closure(true);
                
                let mut mod_encr = | a : &[u8]| -> Vec<u8> {
                    let encr = Box::new(| a : &[u8], k : &[u8]| -> Vec<u8> { Vec::new() });
                    let result = random_key_function(a, block_size as usize, encr);
                    was_ecb = result.1;
                    result.0
                };

                mode = detect_block_mode(& mut mod_encr, block_size);
            }
            if  mode != was_ecb
            {
                num_bad = num_bad + 1;
            }
        }

        assert_eq!(num_bad, 0);
}

pub fn set2_challenge12()
{
    let hidden_plain = encoded_string::encoded_string_from_file("data/s2c12.txt", encoded_string::EncodingType::Base64).unwrap(); 
    let hidden_plain_bytes = hidden_plain.get_bytes().expect("");
    let block_size : usize = 16;
    let key = create_random_key(block_size);

    let mut mod_encr = | a : &[u8] | -> Vec<u8> {
        let mut result : Vec<u8> = Vec::with_capacity(a.len() + hidden_plain_bytes.len());
        result.resize(a.len() + hidden_plain_bytes.len(), 0);

        // construct plain text that is chosen_input || unknown plain text
        result[0..a.len()].copy_from_slice(&a[..]);
        result[a.len()..].copy_from_slice(&hidden_plain_bytes[..]);
        pkcs_7(&mut result, block_size as u32);

        // all these copies is painful
        let encr = | a : &[u8], k : &[u8]| -> Vec<u8> {
        let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
        let mut e = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, 
                                         k,None).expect("");

        e.pad(false);
        temp.resize(a.len() * 2, 0);
        let count = e.update(a, &mut temp).expect("");
        temp.resize(count, 0);
        temp
        };

        // encrypt in ecb mode
        let num_blocks = result.len() / block_size;
        for i in 0..num_blocks {
            let beg : usize = (block_size * i) as usize;
            let end : usize = (block_size * (i + 1)) as usize;
            let enc_block = encr(&result[beg..end], &key);
            result[beg..end].copy_from_slice(&enc_block[..]);
        }

        result
    };

    let plain = ecb_prefix_attack(& mut mod_encr, hidden_plain_bytes.len() as u32);
    let st = encoded_string::encoded_string_from_bytes(&plain, encoded_string::EncodingType::Ascii).expect("").get_val().clone();
    println!("{}\n", st);
}

pub fn set2_challenge13()
{
    let block_size = 16;
    let key = create_random_key(block_size);
    // helper function to take user input email address
    // and return string of form email=foo@bar.com&uid=10&role=user
    let profile_for = | a : &str | -> String {
        let mut result = String::new();
        result.push_str("email=");
        for c in a.chars() {
            if c != '&' && c != '=' {
                result.push(c);
            }
        }
        result.push_str("&uid=10&role=user");
        result
    };

    let mut encr = create_ecb_aes_closure(true);
    let mut decr = create_ecb_aes_closure(false);

    let mut verify_profile = | prof : &[u8] | -> bool {
        let mut admin = false;
        let mut plaintxt = decr(prof, &key);
        pkcs_7_strip(&mut plaintxt, block_size as u32);
        let s = encoded_string_from_bytes(&plaintxt, EncodingType::Ascii).expect("");
        println!("Verifying {:?}\n", s.get_val().clone());
        let kvs = parse_key_value_pairs(&s.get_val());
        for kv_tuple in kvs {
            if kv_tuple.0 == "role" && kv_tuple.1 == "admin" {
                admin = true;
                break;
            }
        }

        admin
    };

    let mut encrypt_profile = | email : &str | -> Vec<u8> {
        let data = profile_for(email);
        println!("Encrypting string {:?}\n", data);
        let s = EncodedString {
            encoding : EncodingType::Ascii,
            val : data
        };
        let mut bytes = s.get_bytes().expect("");
        pkcs_7(&mut bytes, block_size as u32); 
        return encr(&bytes, &key);
    };

    // Here there are two components to crafting an admin profile
    // I need an encrypted profile such that role=admin.  The profile
    // for function strips meta characters (&,=).  So I need to craft a 
    // block that contains "admin" and the padding characters.
    // Then I can create an email address that contains 13mod(block_size) 
    // characters so I can use profile for to get two blocks that when decrypted
    // reads "email=AAAAAAA@A.com&uid=10&role=". Then the previously
    // obtained block can be appended and due to the ECB behavior I will have a
    // profile that verifies as an admin profile.

    let email_str = EncodedString {
        encoding : EncodingType::Ascii,
        val : "AAAA@A.comadmin".to_string()
    };
    let mut b : Vec<u8> = Vec::with_capacity(2 * block_size);
    b.resize(15, 0);

    b[0..15].copy_from_slice(&email_str.get_bytes().expect(""));
    b.resize(26, 11);

    let admin_str = encoded_string_from_bytes(&b, EncodingType::Ascii).expect("");

    let mut admin_block = encrypt_profile(&admin_str.get_val());
    admin_block.truncate(2 * block_size); // remove role=user block that profile_for added
    admin_block.drain(0..block_size); // remove email= block

    let final_email = "AAAAAAA@A.com".to_string(); // 13 characters total

    let mut pre_admin_block = encrypt_profile(&final_email);
    pre_admin_block.truncate(block_size * 2); // remove user block
    pre_admin_block.append(&mut admin_block); // add admin block
    assert_eq!(false, verify_profile(&encrypt_profile(&"acdandrew@gmail.com")));

    assert_eq!(true, verify_profile(&pre_admin_block));
}

pub fn set2_challenge14()
{
    let hidden_plain = encoded_string::encoded_string_from_file("data/s2c12.txt", encoded_string::EncodingType::Base64).unwrap(); 
    let hidden_plain_bytes = hidden_plain.get_bytes().expect("");
    let block_size : usize = 16;
    let key = create_random_key(block_size);
    let random_bytes = create_random_bytes(0, block_size as u32);

    println!("Chose prefix of length {}\n", random_bytes.len());

    let mut mod_encr = | a : &[u8] | -> Vec<u8> {
        let mut result : Vec<u8> = Vec::with_capacity(random_bytes.len() + a.len() + hidden_plain_bytes.len());
        result.resize(random_bytes.len() + a.len() + hidden_plain_bytes.len(), 0);

        // construct plain text that is chosen_input || unknown plain text
        result[0..random_bytes.len()].copy_from_slice(&random_bytes[..]);
        result[random_bytes.len()..(random_bytes.len() + a.len())].copy_from_slice(&a[..]);
        result[(random_bytes.len() + a.len())..].copy_from_slice(&hidden_plain_bytes[..]);
        pkcs_7(&mut result, block_size as u32);

        let mut encr = create_ecb_aes_closure(true);
        //let mut decr = create_ecb_aes_closure(false);
        
        // encrypt in ecb mode
        let num_blocks = result.len() / block_size;
        for i in 0..num_blocks {
            let beg : usize = (block_size * i) as usize;
            let end : usize = (block_size * (i + 1)) as usize;
            let enc_block = encr(&result[beg..end], &key);
            result[beg..end].copy_from_slice(&enc_block[..]);
        }

        result
    };

    let plain = ecb_prefix_attack(& mut mod_encr, hidden_plain_bytes.len() as u32);
    let st = encoded_string::encoded_string_from_bytes(&plain, encoded_string::EncodingType::Ascii).expect("").get_val().clone();
    println!("{}\n", st);
}

pub fn set2_challenge16()
{
    // write encryption function that appends and prepends necessary strings
    let block_size : usize = 16;
    let mut iv : Vec<u8> = Vec::with_capacity(16);
    iv.resize(16,0);

    //let mut encr = create_ecb_aes_closure(true);
    //let mut decr = create_ecb_aes_closure(false);
    let decr = Box::new(| a : &[u8], k : &[u8]| -> Vec<u8> { Vec::new() });
    let encr = Box::new(| a : &[u8], k : &[u8]| -> Vec<u8> { Vec::new() });

    let mut cbc = CBC_Mode::new(encr , decr, block_size as u32, &iv);
    let key = create_random_key(block_size);
    
    // I changed ';' -> '&' to be consistent with key value pairings from an earlier
    // challenge so I could reuse the same key value function
    let prefix = EncodedString {
        encoding : EncodingType::Ascii,
        val : "comment1=cooking%20MCs&userdata=".to_string()
    };
    let postfix = EncodedString {
        encoding : EncodingType::Ascii,
        val : "&comment2=%20like%20a%20pound%20of%20bacon".to_string()
    };
    let mut input : Vec<u8> = Vec::with_capacity(block_size);
    input.resize(block_size, 0);

    let mut crypt : Vec<u8>;
    // create enclosing scope so that mod_encr mutable borrow on cbc expires
    {
     let mut mod_encr = | a : &[u8] | -> Vec<u8> {
    
        let prefix_bytes = prefix.get_bytes().expect("");
        let postfix_bytes = postfix.get_bytes().expect("");
        let capacity = prefix_bytes.len() + postfix_bytes.len() + a.len();
        let mut result : Vec<u8> = Vec::with_capacity(capacity);
        result.resize(capacity, 0);
        result[0..prefix_bytes.len()].copy_from_slice(&prefix_bytes);
        result[prefix_bytes.len()..prefix_bytes.len() + a.len()].copy_from_slice(a);
        result[prefix_bytes.len()+a.len()..].copy_from_slice(&postfix_bytes);

        // construct plain text that is chosen_input || unknown plain text
        pkcs_7(&mut result, block_size as u32);

        // encrypt in ecb mode
        result = cbc.encrypt(&result, &key).expect("");

        result
    };

    crypt = mod_encr(&input);
    }

    let mut verify_profile = | prof : &[u8] | -> bool {
        let mut admin = false;
        let mut plaintxt = cbc.decrypt(prof, &key).expect("");
        pkcs_7_strip(&mut plaintxt, block_size as u32);
        let s = encoded_string_from_bytes(&plaintxt, EncodingType::Ascii).expect("");
        let kvs = parse_key_value_pairs(&s.get_val());
        for kv_tuple in kvs {
            if kv_tuple.0 == "admin" && kv_tuple.1 == "true" {
                admin = true;
                break;
            }
        }

        admin
    };



    let desired_string = EncodedString {
        encoding : EncodingType::Ascii,
        val : "aabcd&admin=true".to_string()
    };
    let mut desired_bytes = desired_string.get_bytes().expect("");
            
    // let  P2 - our input block
    //      C1 - the cipher text output from encrypting block 1
    //      T2 - our desired plain text
    //      C2 - the cipher text output from encrypting block 2 (P2)
    //
    //      For CBC mode C2 = AES_ENCR(P2 XOR C1)
    //                   P2 = AES_DECR(C2) XOR C1
    //                   and since AES_DECR(C2) = P2 XOR C1 if we modify C1 in cipher text
    //                   to be the original C1 XOR T2 then AES_DECR(C2) = P2 XOR C1 XOR C1 XOR T2
    //                   and since P2 is all zeros AES_DECR(C2) ends up being T2.
    inplace_xor_two_vecs(&mut desired_bytes, &crypt[block_size..(2 * block_size)]);
    crypt[block_size..(2*block_size)].copy_from_slice(&desired_bytes);
    assert_eq!(true, verify_profile(&crypt));

    
}


