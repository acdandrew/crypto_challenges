/// A function that pkcs #7 pads a vector according to the provided block size
pub fn pkcs_7(to_modify : &mut Vec<u8>, block_size : u32) {
    let modulus = to_modify.len() as u32 % block_size;
    let bytes_left = block_size - modulus;

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

