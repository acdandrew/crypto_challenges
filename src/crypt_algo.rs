use encryption_utilities::*;
use crypt_util::*;

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
                &(self.enc_func)(&crypt[beg..end], key)[0..self.block_size as usize]);

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
                &(self.dec_func)(&crypt[beg..end], &key[0..self.block_size as usize]));
            
            // xor it in place with the last cipher text
            inplace_xor_two_vecs( & mut plain[beg..end], &self.last_dciph[0..self.block_size as usize]);
            
            // update the last_dciph for next block
            self.last_dciph[0..self.block_size as usize].copy_from_slice(&crypt[beg..end]);
        }

        Some(plain)
    }
}

