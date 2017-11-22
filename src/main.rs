#![allow(dead_code)]
extern crate crypto_pals;
extern crate openssl;
use crypto_pals::encoded_string;
use crypto_pals::encoded_string::*;
use crypto_pals::encryption_utilities::*;
use crypto_pals::crypt_util::*;
use crypto_pals::crypt_algo::*;
use crypto_pals::crypt_break::*;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::io::BufReader;
use openssl::symm;


fn main() { 
    set2_challenge13();
}


fn set1_challenge3()
{
	let crypt  =  encoded_string::EncodedString { 
		encoding : encoded_string::EncodingType::Hex,
		val : "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()
	};

        
    for s in xor_cipher_freq_analysis( &crypt.get_bytes().expect(""))
    {
        println!("{}", s.0);
    }
}

fn set1_challenge4()
{
    let path = Path::new("data/s1c4.txt");

    let file = File::open(&path).unwrap();
    let reader = BufReader::new(&file);
    let mut best_matches : Vec<(String,u8)> = Vec::with_capacity(60);

    for line in reader.lines() {
        match line {
            Ok(s) => {
                let crypt = encoded_string::EncodedString {
                    encoding : encoded_string::EncodingType::Hex,
                    val : s
                };
                best_matches.push(xor_cipher_freq_analysis( &crypt.get_bytes().expect(""))[0].clone());                 
            }
            Err(_) => {}
        }
    }

    best_matches.sort_by_key(|k| k.1);
    //print top one
    for res in best_matches.iter().take(60) {
        println!("{} {}", res.0, res.1);
    }
}

fn set1_challenge5()
{
    let plaintext = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Ascii,
        val :"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_string()
    };
    let key = vec!['I' as u8, 'C' as u8, 'E' as u8];

    let crypt = encoded_string::encoded_string_from_bytes(&xor_repeat_key_encrypt(&plaintext.get_bytes().expect(""), &key), encoded_string::EncodingType::Hex);
    println!("Repeating Key encryption is {:?}", crypt.expect("").get_val());
}

fn set1_challenge6()
{
     let path = Path::new("data/s1c6.txt");

    let file = File::open(&path).unwrap();
    let reader = BufReader::new(&file);

    let mut crypt = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Base64,
        val : String::new()
    };
    for line in reader.lines() {
        match line {
            Ok(s) => {
                crypt.append_val(s);
            }
            Err(_) => {}
        }
    }
    let (plain,key) = xor_repeat_key_break(&crypt.get_bytes().expect(""));
    println!("Result : {:?}", plain.get_val());
    println!("key: {:?}", key);

}

fn set1_challenge7()
{
    let path = Path::new("data/s1c7.txt");
    let file = File::open(&path).unwrap();

    let reader = BufReader::new(&file);

    let mut crypt = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Base64,
        val : String::new()
    };
    for line in reader.lines() {
        match line {
            Ok(s) => {
                crypt.append_val(s);
            }
            Err(_) => {}
        }
    }
   
    let key = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Ascii,
        val : "YELLOW SUBMARINE".to_string()
    };
    let r = symm::decrypt(symm::Cipher::aes_128_ecb(), &key.get_bytes().expect(""), None,
                          &crypt.get_bytes().expect(""));
    match r {
        Ok(v) => {println!("{:?}", encoded_string::encoded_string_from_bytes(&v, encoded_string::EncodingType::Ascii).expect("").get_val());},
        Err(e) => {println!("{:?}", e);}
    }
    //println!("{:?}", symm::decrypt(symm::Cipher::aes_128_ecb(), &key.get_bytes().expect(""), None,
    //                               &crypt.get_bytes().expect("")).unwrap());
}

fn set1_challenge8()
{
    let path = Path::new("data/s1c8.txt");
    let file = File::open(&path).unwrap();
    let mut crypts : Vec<Vec<u8>> = Vec::new();

    let reader = BufReader::new(&file);

    // read in our crypto texts
    for line in reader.lines() {
        match line {
            Ok(s) => {
                let mut crypt = encoded_string::EncodedString {
                    encoding : encoded_string::EncodingType::Hex,
                    val : String::new()
                };
                crypt.append_val(s);
                crypts.push(crypt.get_bytes().expect(""));
            }
            Err(_) => {}
        }
    }

    println!("Challenge 8 dups and block {:?}\n", detect_ecb_aes( &crypts));
}

fn set2_challenge10()
{
    let crypt = encoded_string::encoded_string_from_file("data/s2c10.txt", encoded_string::EncodingType::Base64).unwrap(); 

    let plain = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Ascii,
        val : "YELLOW SUBMARINE".to_string() 
    };
    //create a closure from symm::encrypt and symm::decrypt
    //FIXME These are comically inefficient because of this wierd assert that the library requires
    // that the output vec for the update function be twice the size of its input.  Presumably this
    // is for some mode of encryption that I'm not familiar with.  Rather than having my CBC
    // function handle that weirdness I'd rather just have this copy heavy closure
    let mut decr = | a : &[u8], k : &[u8]| -> Vec<u8> {
        let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
        let mut d = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Decrypt, 
                                         k, None).expect("");
        d.pad(false);
        println!("Before Decrypt\n");
        temp.resize(a.len() * 2, 0);
        let count = d.update(a, &mut temp).expect("");
        temp.resize(count,0); 
        println!("After Decrypt\n");
        temp
    };
    
    let mut encr = | a : &[u8], k : &[u8]| -> Vec<u8> {
        let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
        let mut e = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, 
                                         k,None).expect("");

        println!("Encrypting plain text {:?}\n key : {:?}\n", a,k);
        e.pad(false);
        temp.resize(a.len() * 2, 0);
        let count = e.update(a, &mut temp).expect("");
        temp.resize(count, 0);
        println!("After Encrypt\n");
        temp
    };

    let mut iv : Vec<u8> = Vec::with_capacity(16);
    iv.resize(16,0);
    //create a CBC_Mode structure using those two closures and an IV of all ascii 0s blocksize of
    //16
    let mut cbc = CBC_Mode::new(& mut encr ,& mut decr, 16, &iv);

    //call decrypt method
    let res = encoded_string::encoded_string_from_bytes(&cbc.decrypt(&crypt.get_bytes().expect(""), &plain.get_bytes().expect("")).expect(""), EncodingType::Ascii).expect("");
    println!("Challenge 10 {:?}\n", res.get_val());
}

fn set2_challenge11()
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
                let mut encr = | a : &[u8], k : &[u8]| -> Vec<u8> {
                    let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
                    let mut e = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, 
                                                     k,None).expect("");

                    println!("Encrypting plain text {:?}\n key : {:?}\n", a,k);
                    e.pad(false);
                    temp.resize(a.len() * 2, 0);
                    let count = e.update(a, &mut temp).expect("");
                    temp.resize(count, 0);
                    println!("After Encrypt\n");
                    temp
                };

                let mut mod_encr = | a : &[u8]| -> Vec<u8> {
                    let result = random_key_function(a, block_size as usize, & mut encr);
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

fn set2_challenge12()
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

fn set2_challenge13()
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

/// Create a closure that does ECB AES 128 encryption or decryption
pub fn create_ecb_aes_closure(encrypt : bool) -> Box<FnMut(&[u8], &[u8])-> Vec<u8>>
{
    if !encrypt
    {
        let result = Box::new(| a : &[u8], k : &[u8]| -> Vec<u8> {
            let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
            let mut d = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Decrypt, 
                                             k, None).expect("");
            d.pad(false);
            temp.resize(a.len() * 2, 0);
            let count = d.update(a, &mut temp).expect("");
            temp.resize(count,0); 
            temp
        });
        return result;
    }
    else
    {
        let result = Box::new(| a : &[u8], k : &[u8]| -> Vec<u8> {
            let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
            let mut e = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, 
                                             k,None).expect("");

            e.pad(false);
            temp.resize(a.len() * 2, 0);
            let count = e.update(a, &mut temp).expect("");
            temp.resize(count, 0);
            temp
        });
        return result;
    }
}


