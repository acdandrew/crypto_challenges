use std::vec::Vec;
use std::cmp;

static ENGLISH_FREQUENCIES : [f64;26] = [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074];

pub fn xor_two_vecs( vec_a : & Vec<u8> , vec_b : & Vec<u8> ) -> Vec<u8>
{
    let a = cmp::min(vec_a.len(), vec_b.len()); 
    let mut result : Vec<u8> = Vec::with_capacity(a);
    let mut ita = vec_a.iter();
    let mut itb = vec_b.iter();

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
    let mut input_freq : Vec<u32> = Vec::with_capacity(26); 
    let mut score = 0;
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

    println!("Frequencies from input {:?}", input_freq);
    score 
}

pub fn xor_cipher_freq_analysis( input :& Vec<u8>) -> Vec<Vec<char>>
{
    let mut vec_b : Vec<u8> = Vec::with_capacity(input.len());
    let mut scores : Vec<(u8,u32)> = Vec::with_capacity(256);
    let mut result : Vec<Vec<char>> = Vec::with_capacity(5);
    println!("Xor_cipher_freq_analysis {:?}", input); 
    //
    // Loop over each possible key and score it using english letter frequency
    //
    for candidate in 0..256 {
        println!("Loop {}", candidate); 
        let decrypted = xor_two_vecs(input,  &vec_b);
        scores.push((candidate, score_english_text_freq(&decrypted)));

        vec_b  = vec_b.iter().map(|&x|x+1).collect();
    }
    println!("Passed for loop");    
    scores.sort_by_key(|k| k.1); 
    //generate result list by xoring and as charing
    
    result
}
