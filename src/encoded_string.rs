use std::vec::Vec;

pub enum EncodingType {
	Hex,
	Base64,
	Binary,
}

fn nibble_from_char(val : char ) -> u8
{
    val.to_digit(16).or_else(|| Some(0)).unwrap() as u8
}

fn b64_char_from_six_bits(val : u8)
{
    'a'
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
                if self.val.len() != 0 && ((self.val.len() - 1) % 2 == 0) {
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
        }
    }

    fn convert_to_b64(& mut self) 
    {
        match self.encoding
        {
            EncodingType::Base64 => {},
            _ => {
                let raw_data = self.get_bytes(); //can't this fail?
                let mut new_str = String::with_capacity(raw_data.len() / 6);
                let mut stage = 0;
                let mut current_byte : u8 = 0;
                let mut carry : u8 = 0;
                
                for byte_val in raw_data 
                {
                    match stage 
                    {
                        0 => {
                            current_byte = byte_val & 0b00111111;
                            carry = byte_val >> 6; 
                            new_str.push(b64_char_from_six_bits(current_byte));
                        }
                        _ => {}
                    }
                }

                self.val = new_str;
            }
        }
    }
}
