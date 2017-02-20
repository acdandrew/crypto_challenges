use std::vec::Vec;

pub enum EncodingType {
	Hex,
	Base64,
	Binary,
}

pub struct EncodedString {
	pub encoding : EncodingType,
	pub val : String,
}

pub trait EncodedStringInterface {
    fn get_val(&self) -> & String;
    fn get_bytes(&self) -> Vec<u8>;
}

impl EncodedStringInterface for EncodedString {
    fn get_val(&self) -> & String {
        &self.val
    }

    fn get_bytes(&self) -> Vec<u8>
    {
        if self.val.len() % 2 == 0 {
            let mut v = Vec::with_capacity(self.val.len() / 2);
        

            v
        } else {
            println!("String is not a valid multiple of 2");
            Vec::new()

    }
}
