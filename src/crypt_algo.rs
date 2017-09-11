use encryption_utilities::*;
use crypt_util::*;

/// Struct for CBC mode of an algorithm
pub struct CBC_Mode<T> 
    where T : FnMut(& [u8], & [u8]) -> Vec<u8>
{
    /// A crypt function that takes plain text and key and returns a EBC encrypted block
    enc_func :  T,
    /// A crypt function that takes crypt text and key and returns a EBC decrypted block
    dec_func :  T,
    /// Internal state that holds the last encrypted block ( after CBC transform applied)
    last_eciph : Vec<u8>,
    /// Internal state that holds the last decrypted block ( after CBC transform applied)
    last_dciph : Vec<u8>,
    /// Block size
    block_size : u32
}

/// Implementation of methods for interactin with CBC Mode
impl<T> CBC_Mode<T>
    where T : FnMut(& [u8], & [u8]) -> Vec<u8>
    //where T : FnMut( &Vec<u8>, &Vec<u8>) -> Vec<u8>
{
    /// Returns an initialized CBC Mode struct
    ///
    /// # Arguments
    ///
    ///  'e_func'  - A function that takes a plain text and a key and returns a ECB encrypted block
    ///  'd_func'  - A function that takes a crypt text and a key and returns a ECB decrypted block
    ///  'bsize' - The block size
    ///  'iv'    - An initialization vector.  Function extends to block size with zeros.
    pub fn new(e_func : T, d_func : T, bsize : u32, iv : & Vec<u8>) -> CBC_Mode<T> {
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
    /// 'plain' - the plain text to encrypt in place
    /// 'key;   - the key to use
    pub fn encrypt(mut self,  plain : &[u8] ,key : &[u8]) -> Option<Vec<u8>> {
        let mut crypt : Vec<u8> = Vec::with_capacity(plain.len()); 

        if plain.len() as u32 % self.block_size != 0 {
            return None
        }

        let num_blocks = plain.len() as u32 / self.block_size;

        //TODO write tests for all the component parts
        for i in 0..num_blocks {
            let beg : usize = (self.block_size * i) as usize;
            let end : usize = (self.block_size * (i + 1)) as usize;

            //initialize crypt with last_eciph
            crypt[beg..end].copy_from_slice(&self.last_eciph[0..self.block_size as usize]); // copy
            //xor crypt with plain
            inplace_xor_two_vecs(& mut crypt[beg..end], &plain[beg..end]);

            //inline encrypt into last ciph
            self.last_eciph.copy_from_slice(
                &(self.enc_func)(&crypt[beg..end], key)[0..self.block_size as usize]);

            //update crypt with last ciph
            crypt[beg..end].copy_from_slice(&self.last_eciph[0..self.block_size as usize]);
        }

        Some(crypt)
    }
}

