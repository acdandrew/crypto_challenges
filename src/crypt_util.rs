extern crate rand;

use rand::Rng;

/// A function that pkcs #7 pads a vector according to the provided block size
pub fn pkcs_7(to_modify : &mut Vec<u8>, block_size : u32) {
    let modulus = to_modify.len() as u32 % block_size;
    let bytes_left = block_size - modulus;

   #[allow(unused_variables)]
    for i in 0..bytes_left{
        to_modify.push(bytes_left as u8);
    }
}

/// A function that verifies pkcs #7 padding and strips it
/// bad padding is considered part of the data and the input
/// vec will be unmodified
pub fn pkcs_7_strip(to_modify : &mut Vec<u8>, block_size : u32) -> bool
{
    let mut valid = true;
    let len = to_modify.len() as u32;
    let bytes_to_check = to_modify[(len - 1) as usize] as u32;

    if bytes_to_check as u32 <= block_size - 1
    {
        let begin = len - bytes_to_check;
        for byte in &to_modify[begin as usize .. (len) as usize]
        {
            if bytes_to_check as u8 != *byte
            {
                valid = false;
                break;
            }
        }

        if valid {
            to_modify.truncate((len - bytes_to_check) as usize);
        }
    }

    valid
}

/// XORs two vectors inplace with vec_a holding the result
pub fn inplace_xor_two_vecs( vec_a : &mut[u8] , vec_b : &[u8]) 
{
    let mut index = 0;

    for byte in vec_b {
        if index < vec_a.len() {
            vec_a[index] = vec_a[index] ^ byte;
        }
        index = index + 1;
    }
}

/// Quick and Dirty create random (?) key using rand crate (not cryptographically safe afaik)
/// panics if it cannot create a OsRng object or if there is not a sufficiently 
/// large entropy pool behind the os implementation.  Do not use seriously obviously
pub fn create_random_key( key_size : usize ) -> Vec<u8>
{
    let mut r = rand::OsRng::new().expect("");
    let mut key : Vec<u8> = Vec::with_capacity(key_size);

    key.resize(key_size, 0);  

    r.fill_bytes(&mut key);
    
    key
}

/// Quick and Dirty create byte string key using rand crate (not cryptographically safe afaik)
/// panics if it cannot create a OsRng object or if there is not a sufficiently 
/// large entropy pool behind the os implementation.  Do not use seriously obviously
pub fn create_random_bytes( min_size : u32, max_size : u32) -> Vec<u8>
{
    let mut r = rand::OsRng::new().expect("");
    let mut result : Vec<u8> = Vec::with_capacity(max_size as usize);

    let length = r.next_u32();

    result.resize((min_size + (length % (max_size - min_size))) as usize,0);

    r.fill_bytes(&mut result);

    result
}

/// Parse a string of key values of form key1=val1&key2=val2...
///
/// #Arguments
///
/// 'input' - a string of key and value pairs
///
/// #Output
/// Vec<(String,String)> - a vec containing key value pairs
///
pub fn parse_key_value_pairs(input : &str) -> Vec<(String,String)>
{
    let mut result : Vec<(String,String)> = Vec::new();

    let mut reading_key = true;
    let mut k = String::new();
    let mut v = String::new();
    for c in input.chars() {
       //read until next delimiter 
       match c {
           '&' => {
               // we must be done with value if we read '&'
               if !reading_key {
                result.push((k,v));
                k = String::new();
                v = String::new();
                reading_key = true;
               }
               // do nothing if we aren't reading value
            },
           '=' => {
               // if we reached '=' we must have hit the value part
               if reading_key {
                   reading_key = false;
               }
           },
           _ => {
               if reading_key {
                    k.push(c);
               }
               else
               {
                   v.push(c);
               }
           }
       }
    }

    // handle the last key-value pair
    if !reading_key && v.len() > 0 {
        result.push((k,v));
    }

    result
}

