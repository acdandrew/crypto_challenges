pub mod encoded_string;
pub mod encryption_utilities;
extern crate rand;

#[cfg(test)]
mod tests {


    use encoded_string;
    use encoded_string::*;
    use encryption_utilities::*;
    use std::error::Error;
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;
    use std::io::BufReader;
    use rand;
    use rand::Rng;

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
        assert_eq!(key, xor_repeat_key_break(&crypt)[0].1);


}
