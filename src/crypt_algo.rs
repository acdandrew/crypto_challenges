extern crate rand;

use encryption_utilities::*;
use crypt_util::*;

use rand::Rng;

/// An enum to reperesent cipher block modes of operation
#[derive(Clone, Copy, PartialEq)]
pub enum BlockMode {
    ECB, // Electronic Code Book
    CBC, // Cipher Block Chaining
    INVALID,
}

/// Struct for CBC mode of an algorithm
pub struct CBC_Mode<T1,T2> 
    where T1 : FnMut(& [u8], & [u8]) -> Vec<u8>,
          T2 : FnMut(& [u8], & [u8]) -> Vec<u8>
{
    /// A crypt function that takes plain text and key and returns a EBC encrypted block
    enc_func :  T1,
    /// A crypt function that takes crypt text and key and returns a EBC decrypted block
    dec_func :  T2,
    /// Internal state that holds the last encrypted block ( after CBC transform applied)
    last_eciph : Vec<u8>,
    /// Internal state that holds the last decrypted block ( after CBC transform applied)
    last_dciph : Vec<u8>,
    /// Block size
    block_size : u32
}

/// Implementation of methods for interacting with CBC Mode
impl<T1,T2> CBC_Mode<T1,T2>
    where T1 : FnMut(& [u8], & [u8]) -> Vec<u8>,
          T2 : FnMut(& [u8], & [u8]) -> Vec<u8>
{
    /// Returns an initialized CBC Mode struct
    ///
    /// # Arguments
    ///
    ///  'e_func'  - A function that takes a plain text and a key and returns a ECB encrypted block
    ///  'd_func'  - A function that takes a crypt text and a key and returns a ECB decrypted block
    ///  'bsize' - The block size
    ///  'iv'    - An initialization vector.  Function extends to block size with zeros.
    pub fn new(e_func : T1, d_func : T2, bsize : u32, iv : & Vec<u8>) -> CBC_Mode<T1,T2> {
        let mut c = CBC_Mode { 
            enc_func : e_func,
            dec_func : d_func,
            block_size : bsize,
            last_eciph : iv.clone(),
            last_dciph : iv.clone(),
        };
        c.last_eciph.resize(c.block_size as usize, 0); // resize cipher text to block size filling with 0s
        c.last_dciph.resize(c.block_size as usize, 0);
        c
    }
    ///Encrypts a block in CBC Mode and returns the result
    ///
    /// #Arguments
    ///
    /// 'plain' - the plain text to encrypt
    /// 'key'   - the key to use
    ///
    pub fn encrypt(&mut  self,  plain : &[u8] ,key : &[u8]) -> Option<Vec<u8>> {
        let mut crypt : Vec<u8> = Vec::with_capacity(plain.len()); 
        crypt.resize(plain.len(), 0);
        if plain.len() as u32 % self.block_size != 0 || key.len() as u32 % self.block_size != 0 {
            return None
        }

        let num_blocks = plain.len() as u32 / self.block_size;

        for i in 0..num_blocks {
            let beg : usize = (self.block_size * i) as usize;
            let end : usize = (self.block_size * (i + 1)) as usize;

//            println!("Beg/End {:?} {:?} Last ECiph {:?}, Plain {:?}\n", beg, end, &self.last_eciph[0..self.block_size as usize],
//                    &plain[beg..end]);

            //initialize crypt with last_eciph
            crypt[beg..end].copy_from_slice(&self.last_eciph[0..self.block_size as usize]); // copy
            //xor crypt with plain

            inplace_xor_two_vecs(& mut crypt[beg..end], &plain[beg..end]);

            //inline encrypt into last ciph
            self.last_eciph.copy_from_slice(
                &((self.enc_func)(&crypt[beg..end], key)[0..self.block_size as usize]));
                  

            //update crypt with last ciph
            crypt[beg..end].copy_from_slice(&self.last_eciph[0..self.block_size as usize]);
        }

        Some(crypt)
    }

    ///Decrypts a block in CBC Mode and returns the result
    ///
    /// #Arguments
    ///
    /// 'crypt' - the crypt text to decrypt 
    /// 'key'   - the key to use
    ///
    pub fn decrypt(&mut self, crypt : &[u8], key : &[u8]) -> Option<Vec<u8>> {
        let mut plain : Vec<u8> = Vec::with_capacity(crypt.len());
        plain.resize(crypt.len(), 0);
        if crypt.len() as u32 % self.block_size != 0 || key.len() as u32 % self.block_size != 0 {
            return None
        }

        let num_blocks = crypt.len() as u32 / self.block_size;

        for i in 0..num_blocks {
            let beg : usize = (self.block_size * i) as usize;
            let end : usize = (self.block_size * (i + 1)) as usize;
            println!("Decrypted block {:?}\n", i);
            // decrypt the first block
            plain[beg..end].copy_from_slice(
                &((self.dec_func)(&crypt[beg..end], &key[0..self.block_size as usize])));
            
            // xor it in place with the last cipher text
            inplace_xor_two_vecs( & mut plain[beg..end], &self.last_dciph[0..self.block_size as usize]);
            
            // update the last_dciph for next block
            self.last_dciph[0..self.block_size as usize].copy_from_slice(&crypt[beg..end]);
        }

        Some(plain)
    }
}


/// Oracle Function that takes a plain text and encrypts it under AES with 16 byte key
/// under ECB mode or CBC mode with random iv.  Which mode is chosen with p=.5. Additionally
/// 5-10 bytes are prepending randomly before and after the plaintext.
///
/// 
/// #Arguments
/// 'plain' - the plain text to encrypt
/// 'block_size' - the block size to encrypt
/// 'f' - a function to encrypt plain text block under a given key
///
/// #Outputs
/// (Vec<u8>, bool) - the encrypted text and true if cbc mode
///
/// #Panics
/// - If insufficient entropy exists in OsRng
/// - If plain is not a multiple of block size
pub fn oracle_function<T>(plain : &[u8], block_size : usize,mut f : T) -> (Vec<u8>,BlockMode) 
    where T : FnMut(& [u8], & [u8]) -> Vec<u8>
{
    let mut r = rand::OsRng::new().expect("");

    if plain.len() % block_size != 0
    {
        panic!("Error: oracle function received invalid plain text size\n");
    }
    // create key
    let key = create_random_key(block_size);

    // create modified plain text
    let pre_size = (5 +  r.next_u32() % 6) as usize;
    let post_size = (5 + r.next_u32() % 6) as usize;

    let mut aug_plain : Vec<u8> = Vec::with_capacity(pre_size + post_size + plain.len());
    aug_plain.resize(pre_size + post_size + plain.len(), 0);

    pkcs_7(&mut aug_plain, block_size as u32);

    // fill in pre bytes
    r.fill_bytes(&mut aug_plain[0..pre_size]);

    // convoluted way to copy plain into the right part of the vector
    (&mut aug_plain[(pre_size)..(plain.len() + pre_size)]).copy_from_slice(plain);
    
    // add post bytes
    r.fill_bytes(&mut aug_plain[(pre_size+plain.len())..(pre_size + post_size + plain.len())]);

    let coin = r.next_u32() % 2;
    let mut result : Vec<u8> = Vec::new(); 
   #[allow(unused_variables)]
    let blank = | a : &[u8], k : &[u8]| -> Vec<u8> { Vec::new() };
    let mut mode = BlockMode::ECB;
    if coin == 1
    {
        println!("Oracle Function about to Encrypt CBC {:?}, {:?}\n", aug_plain.len(), &key);
        // if true do cbc mode
        let iv = create_random_key(block_size);
        let mut cbc  = CBC_Mode::new(f,blank, 16, &iv);

        result = cbc.encrypt(&aug_plain, &key).expect("");
        mode = BlockMode::CBC
    }
    else
    {
        println!("Oracle Function about to Encrypt ECB {:?}, {:?}\n", aug_plain.len(), &key);
        result.resize(aug_plain.len(), 0);
        // do ecb mode
        let num_blocks = aug_plain.len() / block_size;
        for i in 0..num_blocks {
            let beg : usize = (block_size * i) as usize;
            let end : usize = (block_size * (i + 1)) as usize;
            let enc_block = f(&aug_plain[beg..end], &key);
            result[beg..end].copy_from_slice(&enc_block[..]);
        }
    }
    (result, mode)
}
