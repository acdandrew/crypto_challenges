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

fn byte_from_b64_char( val : char) -> u8
{
    match val {
        'A'...'Z' => val as u8 - 'A' as u8,
        'a'...'z' => val as u8 - 'a' as u8 + 26,
        '0'...'9' => val as u8 - '0' as u8 + 52,
        '+' => 62,
        '/' => 63,
        '=' => 0,
        _ => panic!("Invalid character in byte from b64 char {}", val) 
    }
}

fn b16_char_from_nibble(val : u8) -> char
{
    match val {
        0...9 => (('0' as u8) + val) as char,
        10...15 => (('a' as u8) + (val - 10)) as char,
        _ => panic!("Invalid character in b16 char from 4 bits {:?}", val),
    }
}

pub struct EncodedString {
	pub encoding : EncodingType,
	pub val : String,
}

pub trait EncodedStringInterface {
    fn get_val(&self) -> & String;
    fn append_val(& mut self, String);
    fn get_bytes(&self) -> Option<Vec<u8>>;
    fn convert_to_b64(& mut self);
}

impl EncodedStringInterface for EncodedString {
    fn get_val(&self) -> & String {
        &self.val
    }

    fn append_val(& mut self, input : String)
    {
        self.val.push_str(input.as_str());
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
                let mut v : Vec<u8> = Vec::with_capacity((self.val.len() / 2 as usize) * 3 as usize);
                
                let mut stage = 0;
                let mut stored_byte : u8 = 0;
                let mut temp : u8 = 0;
                for ch in self.val.chars()
                {
                    match stage {
                        0 => {stored_byte = byte_from_b64_char(ch) << 2; stage = 1;},
                        1 => {
                            temp = byte_from_b64_char(ch);
                            stored_byte = stored_byte + ((temp & 0b00110000) >> 4);
                            v.push(stored_byte);
                            stored_byte = (temp & 0b00001111) << 4;
                            stage = 2;
                        },
                        2 => {
                            temp = byte_from_b64_char(ch);
                            stored_byte = stored_byte + ((temp & 0b00111100) >> 2);
                            v.push(stored_byte);
                            stored_byte = (temp & 0b00000011) << 6;
                            stage = 3;
                        },
                        3 => {
                            stored_byte = stored_byte + byte_from_b64_char(ch);
                            v.push(stored_byte);
                            stage = 0;
                        },
                        _ => {},
                    }
                }

                Some(v)
            },
            EncodingType::Binary => {
                panic!("Used unimplemented function {} {}", file!(), line!());
            },
            EncodingType::Ascii => {
                let mut v : Vec<u8> = Vec::with_capacity(self.val.len());
                for c in self.val.chars()
                {
                    if c as u32 <= u8::max_value() as u32
                    {
                        v.push(c as u8);
                    }
                }
                Some(v)
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

pub fn encoded_string_from_bytes(input : & [u8], enc: EncodingType) -> Option<EncodedString>
{
    let mut result = EncodedString {  encoding : enc, val : String::with_capacity(input.len())};

    match enc{
        EncodingType::Ascii => {
            for a in input {
               result.val.push(*a as char);
            }
        },
        EncodingType::Hex => {
            for a in input {
                result.val.push(b16_char_from_nibble((a & 0xF0) >> 4));
                result.val.push(b16_char_from_nibble(a & 0x0F));
            }
        },
        _ => { panic!("unimplemented function called at {} {}", file!(), line!());
        },
    }

    Some(result)
}
