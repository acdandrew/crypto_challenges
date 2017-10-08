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

/// Create random (?) key using rand crate (not cryptographically safe afaik)
/// panics if it cannot create a OsRng object or if there is not a sufficiently 
/// large entropy pool behind the os implementation
pub fn create_random_key( key_size : usize ) -> Vec<u8>
{
    let mut r = rand::OsRng::new().expect("");
    let mut key : Vec<u8> = Vec::with_capacity(key_size);

    key.resize(key_size, 0); 

    r.fill_bytes(&mut key);
    
    key
}

    
