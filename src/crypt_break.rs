use encryption_utilities::*;
use crypt_algo::*;



pub fn detect_block_mode<T>(mut cipher : T, block_size : u32) -> BlockMode
    where T : FnOnce(& [u8]) -> Vec<u8>
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


