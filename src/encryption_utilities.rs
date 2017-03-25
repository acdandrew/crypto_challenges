use std::vec::Vec;
use std::cmp;
use std::u8;
use encoded_string::*;
use encoded_string;

static ENGLISH_FREQUENCIES : [f64;26] = [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074];

//TODO write map 2 vector function

pub fn hamming_distance(vec_a : &[u8], vec_b : &[u8]) -> u32
{
   let mut result : u32 = 0;
   let ita = vec_a.iter();
   let mut itb = vec_b.iter();
    
   let comparer = ita.map(|x| {
       match itb.next() {
            Some(y) => bit_compare(*x,*y),
            _ => {8},
       }
   });

   for dif in comparer {
       result += dif as u32;
   }

   result
}

pub fn bit_compare(x : u8, y : u8) -> u8
{
    let mut res : u8 = 0;
    let mut xc = x;
    let mut yc = y;

    for _ in 0..7
    {
       if xc & 0x1 != yc & 0x1
       {
           res = res+1;
       }
       xc = xc >> 1;
       yc = yc >> 1;
    }
    res
}

pub fn xor_two_vecs( vec_a : &[u8]  , vec_b : &[u8]) -> Vec<u8>
{
    let a = cmp::min(vec_a.len(), vec_b.len()); 
    let mut result : Vec<u8> = Vec::with_capacity(a);
    let mut ita = vec_a.iter();
    let mut itb = vec_b.iter();
    
    //println!("Xor_two vecs {:?}, {:?}" ,vec_a, vec_b);
    loop 
    {
        let a = ita.next();
        let b = itb.next();

        if a.is_none() || b.is_none()
        {
            break;
        }
        else
        {
            result.push( a.expect("") ^ b.expect("") );
        }
    }

    result
}

pub fn transpose_vec( vec_a : &[u8] , block_size : u32) -> Vec<u8>
{
    let mut result : Vec<u8> = Vec::with_capacity(vec_a.len());

    let num_blocks : u32 = vec_a.len() as u32 / block_size;

    for i in 0..block_size {
        for j in 0..num_blocks
        {
            result.push(vec_a[((j * block_size) + i) as usize]);
        }
    }

    result
}
pub fn score_english_text_freq(input : &Vec<u8>) -> u32
{
    let mut input_freq : Vec<u32> = vec![0; 26]; 
    let mut normal_freq : Vec<f64> = vec![0.0;26];
    let mut score = 0;
    let non_english_penalty = 10;

    for letter in input {
        match *letter as char {
            'a'...'z' => {
                let index = (letter - ('a' as u8)) as usize;
                input_freq[index] = input_freq[index] + 1;
            },
            'A'...'Z' => {
                let index = (letter - ('A' as u8)) as usize;
                input_freq[index] = input_freq[index] + 1;
            },
            ' ' | '.' | '?' => {},
            _ => {score = score + non_english_penalty}
        }
    }

    //
    // attempt at MSE scoring
    //
    for i in 0..26 {
        normal_freq[i] = input_freq[i] as f64 / input.len() as f64;
        score = score + (normal_freq[i] - ENGLISH_FREQUENCIES[i]).powf(2.0) as u32;
    }
    //println!("Exiting score english text with score  {:?}", score); 
    score 
}

pub fn xor_cipher_freq_analysis( input :& Vec<u8>) -> Vec<(String,u32)>
{
    let mut vec_b : Vec<u8> = vec![0;input.len()];
    let mut scores : Vec<(u8,u32)> = Vec::with_capacity(256);
    let mut result : Vec<(String,u32)> = Vec::with_capacity(5);
    //
    // Loop over each possible key and score it using english letter frequency
    //
    for candidate in 0..256 {
        let explicit_type : u32 = candidate; // this is because rust compiler infers candidate as u8
                                             // and does some weird undefined behavior
        let decrypted = xor_two_vecs(input,  &vec_b);
        scores.push((candidate as u8, score_english_text_freq(&decrypted)));
        
        if candidate as u8 !=  u8::max_value()
        {
            vec_b  = vec_b.iter().map(|&x|x+1).collect();
        }
    }
    scores.sort_by_key(|k| k.1); 
    //generate result list by xoring and as charing
    for a in scores.iter().take(5).map( |&x| -> (String,u32) {
        let vec_b : Vec<u8> = vec![x.0;input.len()];
        let str_part = encoded_string::encoded_string_from_bytes(xor_two_vecs(input, &vec_b), EncodingType::Ascii).expect("").val;
        (str_part, x.1)
    })  
    {
        result.push(a);
    }
    result
}

pub fn xor_repeat_key_encrypt( plain : & Vec<u8>, key : & Vec<u8>) -> Vec<u8>
{
    let mut result : Vec<u8> = Vec::with_capacity(plain.len());
    let multiple = key.len();
    let iterations = plain.len() / key.len();
    for i in 0..iterations
    {
        let mut xor = xor_two_vecs(&plain[i * multiple .. (i+1) * multiple], &key[0.. key.len()]);
        result.append(& mut xor);
    }
    let modulus = plain.len() % key.len();
    println!("Modulus is {}", modulus);
    if modulus != 0 {
        let last_slice = (plain.len() / key.len()) * key.len();
        println!("last slice {:?} last key {:?}", &plain[last_slice .. last_slice + modulus], &key[0..modulus]);
        let mut xor = xor_two_vecs(&plain[last_slice .. last_slice + modulus],&key[0.. modulus]);
        result.append(& mut xor)
    }
    result
}


pub fn xor_repeat_key_break( plain : & [u8]) -> String
{
    let mut result = String::with_capacity(plain.len());
    
    let key_size_scores : Vec<(u8,u32)> = Vec::new();
    // determine key size using normalized hamming distance
    for key_size in 2..40 {
       key_size_scores.push((key_size, hamming_distance(&plain[0..key_size], &plain[key_size..2*key_size])/key_size));
    }

    key_size_scores.sort_by_key(|k| k.1);
    println!(" key size scores = {:?}", key_size_scores);
    // transpose blocks

    // solve each block as single character xor
    result
}

