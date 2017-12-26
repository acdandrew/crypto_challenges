pub mod encoded_string;
pub mod encryption_utilities;
pub mod crypt_util;
pub mod crypt_algo;
pub mod crypt_break;
pub mod set1;
pub mod set2;
pub mod set3;

extern crate rand;
extern crate openssl;

#[cfg(test)]
mod tests {


    use encoded_string;
    use encoded_string::*;
    use encryption_utilities::*;
    use crypt_util::*;
    use crypt_algo::*;
    use crypt_break::*;
    use std::error::Error;
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;
    use std::io::BufReader;
    use rand;
    use rand::Rng;
    use openssl::symm;
    use openssl;

    #[test]
    fn test_hex_to_b64() {
        let byte = vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];

        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();

        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        
         
        let mut our_string  =  encoded_string::EncodedString { 
            encoding : encoded_string::EncodingType::Hex,
            val : hex
        };

        assert_eq!(our_string.get_bytes().expect(""), byte);
        our_string.convert_to_b64();
        assert_eq!(*our_string.get_val(), b64);
        
            }

    #[test]
    fn test_encoded_string_from_bytes() {
            let ascii_string = encoded_string::EncodedString {
                encoding: encoded_string::EncodingType::Ascii,
                val : "Andrew is the best!".to_string()
            };

            let b64_string = ascii_string.get_bytes().expect("");
            assert_eq!(&"Andrew is the best!", 
                       encoded_string::encoded_string_from_bytes(&b64_string, 
                                        encoded_string::EncodingType::Ascii).expect("").get_val());
    }
    
    #[test]
    fn test_b64_to_bytes()
    {
        let b64_string = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Base64,
            val : "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string()
        };
        let byte = vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];
        assert_eq!(b64_string.get_bytes().expect(""), byte);
    }


    #[test]
    fn test_xor() {
        
        let string_a  =  encoded_string::EncodedString { 
            encoding : encoded_string::EncodingType::Hex,
            val : "1c0111001f010100061a024b53535009181c".to_string() 
        };

        let string_b  =  encoded_string::EncodedString { 
            encoding : encoded_string::EncodingType::Hex,
            val : "686974207468652062756c6c277320657965".to_string()
        };

        let string_result  =  encoded_string::EncodedString { 
            encoding : encoded_string::EncodingType::Hex,
            val :"746865206b696420646f6e277420706c6179".to_string()
        };

        assert_eq!(xor_two_vecs(&string_a.get_bytes().expect(""), &string_b.get_bytes().expect("")),
                   string_result.get_bytes().expect(""));
    }

    #[test]
    fn test_repeat_key_xor() {
        let plaintext = encoded_string::EncodedString {
                encoding : encoded_string::EncodingType::Ascii,
                val :"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_string()
            };
        let key = vec!['I' as u8, 'C' as u8, 'E' as u8];

        let string_result = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Hex,
            val : "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".to_string()
        };

        let crypt = encoded_string::encoded_string_from_bytes(&xor_repeat_key_encrypt(&plaintext.get_bytes().expect(""), &key), encoded_string::EncodingType::Hex);

        assert_eq!(crypt.expect("").get_val(), string_result.get_val());
    }

    #[test]
    fn test_hamming_distance() {
        let string_a = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : "this is a test".to_string()
        };
        let string_b = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : "wokka wokka!!!".to_string()
        };

            assert_eq!(hamming_distance(&string_a.get_bytes().expect(""), &string_b.get_bytes().expect("")), 37);
    }


    #[test]
    fn test_transpose_vec() {
        let input : Vec<u8> = vec![ 1, 2, 3,4 ,5 ,6 ,7,8, 9];
        let result : Vec<u8> = vec![1,4,7,2,5,8,3,6,9];

        assert_eq!(result, transpose_vec(&input, 3));
    }

    #[test]
    fn test_xor_cipher_analysis() {
        let path = Path::new("data/first_five_woodlanders.txt");

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(&file);

        let mut plain = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : String::new()
        };
        for line in reader.lines() {
            match line {
                Ok(mut s) => {
                    if s.ends_with("\n")
                    {
                        s.pop();
                    }
                    plain.append_val(s);
                }
                Err(_) => {}
            }
        }
        // generate random key
        let mut key = 0xc7;
        
        let key_vec : Vec<u8> = vec![key];
        // encrypt the plain text
        let crypt = xor_repeat_key_encrypt(&plain.get_bytes().expect(""), &key_vec);

        // assert that analysis finds the right key
        assert_eq!(key, xor_cipher_freq_analysis(&crypt)[0].1);
    }

    #[test]
    fn test_xor_repeat_cipher_analysis() {
        let path = Path::new("data/first_five_woodlanders.txt");

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(&file);

        let mut plain = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : String::new()
        };
        for line in reader.lines() {
            match line {
                Ok(mut s) => {
                    if s.ends_with("\n")
                    {
                        s.pop();
                    }
                    plain.append_val(s);
                }
                Err(_) => {}
            }
        }
        // generate random key
        
        let key_vec : Vec<u8> = vec![0xc7, 0xfa, 0x3b];
        // encrypt the plain text
        let crypt = xor_repeat_key_encrypt(&plain.get_bytes().expect(""), &key_vec);

        // assert that analysis finds the right key
        assert_eq!(key_vec, xor_repeat_key_break(&crypt).1);
    }

    #[test]
    fn test_detect_duplicates() {
        let a : Vec<u8> = vec![1,2,3,4,5,6,7,8,3,3,3,3,1,2,3,4,7,8,9,0,3,3,3,3];

        // assert that we get four matches for t with blocksize of 4
        // the abcd blocks match each other and the beef blocks do
        assert_eq!(4, detect_duplicates(&a, 4));
    }

    #[test]
    fn test_pkcs_7_padding() {
        let mut plain = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : "YELLOW SUBMARINE".to_string() 
        };

        let mut unpadded_bytes = plain.get_bytes().expect("");
        let mut padded_bytes = plain.get_bytes().expect("");
        padded_bytes.push(0x04);
        padded_bytes.push(0x04);
        padded_bytes.push(0x04);
        padded_bytes.push(0x04);
        pkcs_7(& mut unpadded_bytes, 20); 
        assert_eq!(unpadded_bytes, padded_bytes);
    }

    #[test]
    fn test_cbc_mode() {
        let mut key = encoded_string::EncodedString {
            encoding : encoded_string::EncodingType::Ascii,
            val : "YELLOW SUBMARINE".to_string() 
        };

        let mut plain = encoded_string::EncodedString {
            encoding: encoded_string::EncodingType::Ascii,
            val : "Hello Andrew FrdHello Andrew Frd".to_string()
        };

        openssl::init();
        println!("Starting plain text {:?}\n key : {:?}\n", plain.get_bytes().expect(""),
        key.get_bytes().expect(""));

        let mut iv : Vec<u8> = Vec::with_capacity(16);
        iv.resize(16,0);
        //create a CBC_Mode structure using those two closures and an IV of all ascii 0s blocksize of
        //16
        let encr = create_ecb_aes_closure(true);
        let decr = create_ecb_aes_closure(false);
        let mut cbc = CBC_Mode::new(encr , decr, 16, &iv);
        let cbc_crypt = cbc.encrypt(&plain.get_bytes().expect(""), &key.get_bytes().expect(""));
        //assert_eq!(cbc_crypt.expect(""), cout);

        let plain2 = cbc.decrypt(&cbc_crypt.expect(""), &key.get_bytes().expect(""));
        assert_eq!(plain2.expect(""),plain.get_bytes().expect("")); 
    }

    #[test]
    fn test_create_random_key()
    {
        let key_size : usize = 32;

        assert_ne!(create_random_key(key_size), create_random_key(key_size));
        assert_eq!(key_size, create_random_key(key_size).len());
    }

    // This test needs to be rewritten.  I originally wrote it to use a side effect in mod_encr
    // to let the test know what the true block mode was.  However this violates the safety rules
    // of Rust.
    #[test]
    fn test_detect_block_mode()
    {
//        let num_test = 1;
//        let block_size = 16;
//        let mut num_bad = 0;
//        for i in 0..num_test {
//            let mut was_ecb = BlockMode::ECB;
//            let mut mode = BlockMode::ECB;
//
//            // create enclosing scope so that closure can expire
//            // after its used in detect_block_mode thereby releasing mut borrow of was_ecb
//            {
//                let encr = | a : &[u8], k : &[u8]| -> Vec<u8> {
//                    let mut temp : Vec<u8> = Vec::with_capacity(a.len() * 2);
//                    let mut e = symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, 
//                                                     k,None).expect("");
//
//                    println!("Encrypting plain text {:?}\n key : {:?}\n", a,k);
//                    e.pad(false);
//                    temp.resize(a.len() * 2, 0);
//                    let count = e.update(a, &mut temp).expect("");
//                    temp.resize(count, 0);
//                    println!("After Encrypt\n");
//                    temp
//                };
//
//                let mod_encr = | a : &[u8]| -> Vec<u8> {
//                    let result = random_key_function(a, block_size as usize, & encr);
//                    was_ecb = result.1;
//                    result.0
//                };
//
//                mode = detect_block_mode(&mut mod_encr, block_size);
//            }
//            if  mode != was_ecb
//            {
//                num_bad = num_bad + 1;
//            }
//        }
//
//        assert_eq!(num_bad, 0);
    }

    #[test]
    fn test_parse_key_value_pairs()
    {
        let input = "dog=cat&bill=fill&var&en=lightbulb".to_string();
        let mut res : Vec<(String,String)> = Vec::new();
        res.push(("dog".to_string(),"cat".to_string()));
        res.push(("bill".to_string(),"fill".to_string()));
        res.push(("varen".to_string(),"lightbulb".to_string()));

        assert_eq!(res, parse_key_value_pairs(&input));
    }

    #[test]
    fn test_pkcs_7_strip()
    {
        let block_size = 16;

        let mut invalid: Vec<u8> = Vec::with_capacity(block_size * 2);
        invalid.resize((block_size * 2) as usize, 0xA);
        invalid[(block_size * 2) - 1] = 0x5;
        let original_inv = invalid.clone();

        let mut valid : Vec<u8> = vec![1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,12,12,12,15,7,7,7,7,7,7,7];
        pkcs_7_strip(&mut invalid, block_size as u32);
        assert_eq!(original_inv, invalid);
        pkcs_7_strip(&mut valid, block_size as u32);
        assert_eq!(valid,vec![1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,12,12,12,15]);
    }


}
