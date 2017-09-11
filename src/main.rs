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
    set1_challenge8();
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

