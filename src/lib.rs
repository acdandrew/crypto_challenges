pub mod encoded_string;
pub mod encryption_utilities;


#[cfg(test)]
mod tests {
    use encoded_string;
    use encoded_string::*;
    use encryption_utilities::*;

    #[test]
    fn test_hex_to_b64() {
        let byte = vec![73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109];

        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();

        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
        
         
        let mut our_string  =  encoded_string::EncodedString { 
            encoding : encoded_string::EncodingType::Hex,
            val : hex
        };

        assert_eq!(our_string.get_bytes(), Some(byte));
        our_string.convert_to_b64();
        assert_eq!(*our_string.get_val(), b64);
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
}
