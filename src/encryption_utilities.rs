use std::vec::Vec;
use std::cmp;
use std::u8;
use encoded_string::*;
use encoded_string;

static ENGLISH_FREQUENCIES : [f64;26] = [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074];

pub fn xor_two_vecs( vec_a : & Vec<u8> , vec_b : & Vec<u8> ) -> Vec<u8>
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

pub fn score_english_text_freq(input : &Vec<u8>) -> u32
{
    let mut input_freq : Vec<u32> = vec![0; 26]; 
    let mut normal_freq : Vec<f64> = vec![0.0;26];
    let mut score = 0;
    //println!("Entered score with input {:?}", input);
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
            _ => {}
        }
    }

    for i in 0..26 {
        normal_freq[i] = input_freq[i] as f64 / input.len() as f64;
        score = score + (normal_freq[i] - ENGLISH_FREQUENCIES[i]).powf(2.0) as u32;
    }
    println!("Exiting score english text with score  {:?}", score); 
    score 
}

pub fn xor_cipher_freq_analysis( input :& Vec<u8>) -> Vec<String>
{
    let mut vec_b : Vec<u8> = vec![0;input.len()];
    let mut scores : Vec<(u8,u32)> = Vec::with_capacity(256);
    let mut result : Vec<String> = Vec::with_capacity(5);
    println!("Xor_cipher_freq_analysis {:?}", input); 
    //
    // Loop over each possible key and score it using english letter frequency
    //
    for candidate in 0..256 {
        let decrypted = xor_two_vecs(input,  &vec_b);
        scores.push((candidate as u8, score_english_text_freq(&decrypted)));
        
        if candidate !=  u8::max_value()
        {
            vec_b  = vec_b.iter().map(|&x|x+1).collect();
        }
    }
    println!("After testing scores are {:?}", scores);
    scores.sort_by_key(|k| k.1); 
    //generate result list by xoring and as charing
    for a in scores.iter().take(5).map( |&x| -> String{
        println!("Highest Scores were {}", x.0);
        let vec_b : Vec<u8> = vec![x.0;input.len()];
        encoded_string::encoded_string_from_bytes(xor_two_vecs(input, &vec_b), EncodingType::Ascii).expect("").val
    })  
    {
        result.push(a);
    }
    result
}
