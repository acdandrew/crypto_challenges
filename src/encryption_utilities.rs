use std::vec::Vec;
use std::cmp;


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
