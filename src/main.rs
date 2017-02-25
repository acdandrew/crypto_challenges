extern crate crypto_pals;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

use crypto_pals::encoded_string;
use crypto_pals::encoded_string::*;


fn main() { 
	let mut b64  =  encoded_string::EncodedString { 
		encoding : encoded_string::EncodingType::Hex,
		val : "".to_string()
	};

	let f = match File::open("data/s1c1.txt") {
		Ok(file) => {file},
		Err(e) => { panic!("Failed to open file {:?} with error {}\n",std::env::current_dir(), e) },
	};
		
	let mut reader = BufReader::new(f);
	let mut buffer = String::new();

	// read a line
	if let Err(e) = reader.read_line(&mut buffer) {
		println!("Read line failed {}\n", e);
		panic!("Exiting!\n");
    }

	
	b64.val = buffer;	
	println!("Test func returns : {}", b64.get_val());
    println!("Bytes are : {:?}", b64.get_bytes());
}


