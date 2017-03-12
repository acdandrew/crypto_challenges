use std::vec::Vec;

#[derive(Clone, Copy)]
pub enum EncodingType {
	Hex,
	Base64,
	Binary,
    Ascii,
}

fn nibble_from_char(val : char ) -> u8
{
    val.to_digit(16).or_else(|| Some(0)).unwrap() as u8
}

fn b64_char_from_six_bits(val : u8) -> char
{
    match val {
        0...25 => (('A' as u8) + val) as char,
        26...51 => (('a' as u8) + (val - 26)) as char,
        52...61 => (('0' as u8) + (val - 52)) as char,
        62 => '+',
        63 => '/',
        255 => '-',
        _ => panic!("Invalid character in b64 char from 6 bits {:?}", val),
    }
     
}


pub struct EncodedString {
	pub encoding : EncodingType,
	pub val : String,
}

pub trait EncodedStringInterface {
    fn get_val(&self) -> & String;
    fn get_bytes(&self) -> Option<Vec<u8>>;
    fn convert_to_b64(& mut self);
}

impl EncodedStringInterface for EncodedString {
    fn get_val(&self) -> & String {
        &self.val
    }

    fn get_bytes(& self) -> Option<Vec<u8>>
    {
        //TODO Implement missing conversion functions
        //TODO Implement returning Result instead of Option
        match self.encoding {
            EncodingType::Hex => { 
                if self.val.len() != 0 && ((self.val.len()) % 2 == 0) {
                    let mut v : Vec<u8> = Vec::with_capacity(self.val.len() / 2);
                    let mut high_order = false;
                    let mut current_byte = 0;
                    for nibble_char in self.val.chars()
                    {
                        let nibble_val = nibble_from_char(nibble_char);
                        if high_order
                        {
                            current_byte += nibble_val; 
                            v.push(current_byte);
                        }
                        else
                        {
                            current_byte = nibble_val << 4; 
                        }
                        high_order = !high_order;
                    }

                    Some(v)
                } else {
                    println!("String is not a valid multiple of 2. Was {}", self.val.len());
                    None 
                }
            },
            EncodingType::Base64 => {
                panic!("Used unimplemented function {} {}", file!(), line!());
            },
            EncodingType::Binary => {
                panic!("Used unimplemented function {} {}", file!(), line!());
            },
            EncodingType::Ascii => {
                panic!("Used unimplemented function {} {}", file!(), line!());
            },
        }
    }

    fn convert_to_b64(& mut self) 
    {
        match self.encoding
        {
            EncodingType::Base64 => {},
            _ => {
                //TODO remove unwrap
                let raw_data = self.get_bytes().unwrap(); //can't this fail?
                let mut new_str = String::with_capacity(raw_data.len() / 6);
                let mut stage = 0;
                let mut current_byte : u8 = 0;
                let mut carry : u8 = 0;
                
                for byte_val in raw_data 
                {
                    match stage 
                    {
                        0 => {
                            current_byte = (byte_val & 0b11111100) >> 2;
                            carry = byte_val & 0b00000011; 
                            new_str.push(b64_char_from_six_bits(current_byte));
                            stage = 1;
                        }
                        1 => {
                            current_byte = (carry << 4) + ((byte_val & 0b11110000) >> 4);
                            carry = byte_val & 0b00001111;
                            new_str.push(b64_char_from_six_bits(current_byte));
                            stage = 2;
                        }
                        2 => {
                            current_byte = (carry << 2) + ((byte_val & 0b11000000) >> 6);
                            new_str.push(b64_char_from_six_bits(current_byte));
                            new_str.push(b64_char_from_six_bits(byte_val & 0b00111111));
                            stage = 0;
                        }
                        _ => {}
                    }
                }

                self.val = new_str;
            }
        }
    }
}

pub fn encoded_string_from_bytes(input : Vec<u8>, enc: EncodingType) -> Option<EncodedString>
{
    let mut result = EncodedString {  encoding : enc, val : String::with_capacity(input.len())};

    match enc{
        EncodingType::Ascii => {
            for a in input {
               result.val.push(a as char);
            }
        },
        _ => { panic!("unimplemented function called at {} {}", file!(), line!());
        }
    }

    Some(result)
}
