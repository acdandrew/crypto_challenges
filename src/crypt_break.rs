use encryption_utilities::*;
use crypt_algo::*;

/// Function that detects block mode of a cipher (even if that cipher appends and prepends
/// randomly to our chosen plaintext) by checking is blocks are the same.  Choosing 3 * blocksize
/// means that we must have two identical blocks regardless of prepended strings.
///
/// #Arguments
/// 'cipher' - the cipher function to check
/// 'block_size' - the block size of the cipher
/// 
/// #Outputs
/// BlockMode - the suspected block mode of the cipher
pub fn detect_block_mode<T>(cipher : & mut T, block_size : u32) -> BlockMode
    where T : FnMut(& [u8]) -> Vec<u8>
{
    // create chosen plain text.
    println!("Entered detect block mode\n");
    let mut chosen_plain : Vec<u8> = Vec::with_capacity((3 * block_size) as usize); 
    chosen_plain.resize((3 * block_size) as usize, 0xFF);

    let output : Vec<u8> = cipher(&chosen_plain).clone();

    println!("About to exit detect block mode\n");
    match detect_duplicates(&output, block_size)
    {
        0 => { BlockMode::CBC },
        _ => { BlockMode::ECB }
    }
}

/// Function that attacks an ecb function that appends an unknown plaintext to our
/// chosen plaintext decrypting it a byte at a time.  This is done by controlling
/// where block boundaries lie.
///
/// #Arguments
/// 'cipher' - the cipher function to attack
/// 'block_size' - the block size of the cipher
/// 'num_bytes' - number of bytes to extract
///
/// #Outputs
/// Vec<u8> - extracted plaintext
pub fn ecb_prefix_attack<T>(cipher : & mut T,  num_bytes : u32) -> Vec<u8>
    where T : FnMut(& [u8]) -> Vec<u8>
{
    let mut result : Vec<u8> = Vec::new();

    let block_size = detect_block_size(cipher);

    let mode_type = detect_block_mode(cipher, block_size as u32);

    // if we have a valid setup to extract bytes
    if mode_type == BlockMode::ECB && block_size > 0
    {
        println!("Valid setup for breaking ecb\n");
        let blocks = num_bytes / block_size as u32 + 1;
        let mut found_bytes = 0;

        // choose plaintxt as large as the buffer to find
        let mut chosen_plaintxt : Vec<u8> = Vec::with_capacity(blocks as usize * block_size);
        let mut known_bytes : Vec<u8> = Vec::with_capacity(blocks as usize * block_size);
        chosen_plaintxt.resize(blocks as usize * block_size as usize - 1, 0xAA);
        known_bytes.resize(blocks as usize * block_size as usize - 1, 0xAA);

        // while we haven't extracted all the bytes
        while found_bytes < num_bytes
        {
            // get the encrypted blocks consisting of chosen_plaintxt.len() known bytes and one target unknown byte
            let chosen_crypt = cipher(&chosen_plaintxt);

            // brute force target byte
            known_bytes.push(0x0);
            for i in 0..256
            {
                #[allow(unused_variables)]
                let explicit_type : u32 = i;
                let len = known_bytes.len();

                known_bytes[len - 1] = i as u8;
                // if we have a match add it to the result and go to next iteration
                let guess_crypt = cipher(&known_bytes);
                if guess_crypt[len-block_size..len] == chosen_crypt[len-block_size..len]
                {
                    result.push(i as u8);
                    known_bytes[len-1] = i as u8;
                    found_bytes = found_bytes + 1;
                    break;
                }
            }

            chosen_plaintxt.drain(0..1);
            known_bytes.drain(0..1);
        }
    }
    
    result
}

/// Function that detects block size of a cipher
///
/// #Arguments
/// 'cipher' - the cipher function to attack
///
/// #Outputs
/// usize - the block size
pub fn detect_block_size<T>(cipher : & mut T) -> usize
    where T : FnMut(& [u8]) -> Vec<u8>
{
    let mut a : Vec<u8> = Vec::new();

    a.push(0xFF);

    let initial_size = cipher(&a).len();
    let mut next_block_size = initial_size;

    while next_block_size == initial_size
    {
        a.push(0xFF);
        next_block_size = cipher(&a).len();
    }

    (next_block_size - initial_size) as usize
}
