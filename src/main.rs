#![allow(dead_code)]
extern crate crypto_pals;
use crypto_pals::encoded_string;
use crypto_pals::encoded_string::*;
use crypto_pals::encryption_utilities::*;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::io::BufReader;

fn main() { 
    //set1_challenge4();
    set1_challenge6();
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
    let mut reader = BufReader::new(&file);
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
    let mut reader = BufReader::new(&file);

    let mut crypt = encoded_string::EncodedString {
        encoding : encoded_string::EncodingType::Base64,
        val : String::new()
    };
    for line in reader.lines() {
        match line {
            Ok(mut s) => {
                if s.ends_with("\n")
                {
                    s.pop();
                }
                crypt.append_val(s);
            }
            Err(_) => {}
        }
    }
    //println!("Trimmed b64 string {:?}", crypt.get_val());
    println!("Result : {:?}",xor_repeat_key_break(&crypt.get_bytes().expect("")).expect("").get_val());
}



