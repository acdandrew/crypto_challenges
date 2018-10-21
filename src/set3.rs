use std::vec::Vec;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::io::BufReader;
use crypt_algo::*;

pub fn set3_challenge17()
{
    // read strings from file
    let path = Path::new("data/s3c17.txt");
    let num_strings = 10;
        
    let mut strings : Vec<String> = Vec::with_capacity(num_strings);
    match File::open(&path) {
        Ok(file) => {
            let reader = BufReader::new(&file);

            for line in reader.lines() {
                match line {
                   Ok(s) => {
                       strings.push(s);
                   },
                   Err(_) => {}
                }
            }
        }
        Err(_) => { println!("Error missing set3 data file\n"); }
    }


    // generate function to choose random string from 10 provided and encrypt it under consistent
    let encr = create_ecb_aes_closure(true);
    let decr = create_ecb_aes_closure(false);
    
    let mut iv : Vec<u8> = Vec::with_capacity(16);
    iv.resize(16,0);
    let mut cbc = CBC_Mode::new(encr , decr, 16, &iv);


    let mut r = rand::OsRng::new().expect("");
    let num_strings = strings.len();
    let chosen_string = &strings[r.next_u32() % num_strings];
    // write function to return true or false if padding is valid after decryption

    // write code to modify cipher text and decrypt given string
    println!("Done\n");
}

