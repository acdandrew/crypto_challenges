extern crate crypto_pals;

use crypto_pals::encoded_string;
use crypto_pals::encoded_string::*;
use crypto_pals::encryption_utilities::*;


fn main() { 
	let crypt  =  encoded_string::EncodedString { 
		encoding : encoded_string::EncodingType::Hex,
		val : "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string()
	};

        
    xor_cipher_freq_analysis( &crypt.get_bytes().expect(""));
}


