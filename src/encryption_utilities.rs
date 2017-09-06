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
    let non_english_penalty = 100;

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
    // attempt at chi squared pearson scoring
    //
    for i in 0..26 {
        normal_freq[i] = input_freq[i] as f64 / input.len() as f64;
        score = score + ((normal_freq[i] - ENGLISH_FREQUENCIES[i]).powf(2.0)/ENGLISH_FREQUENCIES[i]) as u32;
    }
    //println!("Exiting score english text with score  {:?}", score); 
    score 
}

pub fn xor_cipher_freq_analysis( input :& [u8]) -> Vec<(String,u8)>
{
    let mut vec_b : Vec<u8> = vec![0;input.len()];
    let mut scores : Vec<(u8,u32)> = Vec::with_capacity(256);
    let mut result : Vec<(String,u8)> = Vec::with_capacity(5);
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
    for a in scores.iter().take(5).map( |&x| -> (String,u8) {
        let vec_b : Vec<u8> = vec![x.0;input.len()];
        let str_part = encoded_string::encoded_string_from_bytes(&xor_two_vecs(&input, &vec_b), EncodingType::Ascii).expect("").val;
        (str_part, x.0 as u8)
    })  
    {
        //println!("{:?}\n", a.0);
        result.push(a);
    }
    result
}

pub fn xor_repeat_key_encrypt( plain : & [u8], key : & Vec<u8>) -> Vec<u8>
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
    //println!("Modulus is {}", modulus);
    if modulus != 0 {
        let last_slice = (plain.len() / key.len()) * key.len();
        //println!("last slice {:?} last key {:?}", &plain[last_slice .. last_slice + modulus], &key[0..modulus]);
        let mut xor = xor_two_vecs(&plain[last_slice .. last_slice + modulus],&key[0.. modulus]);
        result.append(& mut xor)
    }
    result
}


pub fn xor_repeat_key_break( plain : & [u8] ) -> (EncodedString, Vec<u8>)
{
    let mut key_size_scores : Vec<(u8,f32)> = Vec::new();
    let mut result_scores : Vec<(Vec<u8>,u32)> = Vec::new();
    // determine key size using normalized hamming distance
    for key_size in 2..40 {
       let mut total_edit_distance : u32 = 0;
       //for i in 0..4 {
            //total_edit_distance += hamming_distance(&plain[i * key_size as usize..(i + 1) * key_size as usize], &plain[(i + 1) * key_size as usize.. (i + 2) * key_size as usize]);
       //}
       let explicit_type : u32 = key_size;
       total_edit_distance  = hamming_distance(&plain[0..(4 * key_size) as usize], &plain[((4 *key_size) as usize)..((8 * key_size) as usize)]);
       key_size_scores.push((key_size as u8, (total_edit_distance as f32) / (key_size as f32)));
    }

    key_size_scores.sort_by(|a,b| a.1.partial_cmp(&b.1).unwrap());
    println!(" key size scores = {:?}, total length {}", key_size_scores, plain.len());

    // transpose blocks
    for p in key_size_scores.iter().take(4)
    {
        let mut key_vec : Vec<u8> = Vec::new(); 
        //let key_size = key_size_scores[0].0;
        let key_size = p.0;
        let trans = transpose_vec(plain, key_size as u32);

        // solve each block as single character xor
        let block = plain.len() as u32 / key_size as u32;
        let key_size : u32 = key_size as u32;
        println!("Key candidate length {} block length {}", p.0, block);
        for i in 0..key_size 
        {
           //println!("{:?} checking key number", i);
           key_vec.push(xor_cipher_freq_analysis(&trans[(i * block) as usize .. ((i + 1) * block) as usize])[0].1 as u8);
        }

        // apply key
        let candidate = encoded_string_from_bytes(&xor_repeat_key_encrypt(plain, &key_vec),
                                                  EncodingType::Ascii).expect("");
        let score = score_english_text_freq(&candidate.get_bytes().expect(""));
        result_scores.push((key_vec,score));
        //println!("\n Key size {} {:?}\n",p.0,encoded_string_from_bytes(&xor_repeat_key_encrypt(plain, &key_vec), EncodingType::Ascii).expect("").get_val());

        // score resulting plain text and keep results
    }
    
    result_scores.sort_by_key(|k| k.1);

    // return best scoring plain text and key
    (encoded_string_from_bytes(&xor_repeat_key_encrypt(plain, &result_scores[0].0), EncodingType::Ascii).expect(""), result_scores[0].0.clone())
}

pub fn detect_duplicates(buf : &[u8] ,block_size : u32) -> (u32)
{
    let mut result = 0;
    // if we are properly divisible by block size
    if buf.len() as u32 % block_size == 0 {
        // for each block
        let block_num : u32 = (buf.len() / block_size as usize) as u32;
        for i in 0..block_num {
            // for each other block
            for j in 0..block_num {
                //if two slices are equal (and not the same index) inc result
                if i != j && 
                    buf[(i * block_size) as usize .. ((i + 1) * block_size) as usize] ==
                    buf[(j * block_size) as usize .. ((j + 1) * block_size) as usize] {
                        result = result + 1;
                }
            }
        }
    }
    else {
        println!("Did not check since mod is {}\n", buf.len() as u32 % block_size);
    }
    result
}

pub fn detect_ecb_aes( crypts :& [Vec<u8>] ) -> (String, u32)
{
    // map each Vec<u8> -> Vec<int> where int is number of duplicate blocks
    let mut counts : Vec<(Vec<u8>, u32)> = 
                crypts.iter().map(|x| -> (Vec<u8>, u32) {
                    (x.clone(), detect_duplicates(&x, 16))
                }).collect(); 

    counts.sort_by_key(|k| -1 as i32 * k.1 as i32);

    for a in counts.iter().take(5) {
        println!("Highest counts are {:?}\n", a.1);
    }
    let result = encoded_string::encoded_string_from_bytes(&counts[0].0, EncodingType::Hex).expect("").get_val().clone();
    let count = counts[0].1;
    (result, count)
}
