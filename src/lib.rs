
pub trait Word:
    Clone
    + Copy
    + num::traits::WrappingAdd
    + num::traits::WrappingSub
    + std::fmt::Debug
    + std::cmp::PartialEq
    + std::ops::BitAnd<Output = Self>
    + std::ops::AddAssign
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
    + std::ops::Shl<Output = Self>
    + std::ops::Shr<Output = Self>
{
    const ZERO: Self;
    const P: Self;
    const Q: Self;

    const BYTES: usize;

    fn from_u8(val: u8) -> Self;
    fn from_usize(val: usize) -> Self;
}

impl Word for u8 {
    const ZERO: Self = 0u8;
    const P: Self = 0u8;
    const Q: Self = 0u8;

    const BYTES: usize = 1usize;

    fn from_u8(val: u8) -> Self {
        val
    }

    fn from_usize(val: usize) -> Self {
        val as u8
    }
}

impl Word for u32 {
    const ZERO: Self = 0u32;
    const P: Self = 0xb7e15163u32;
    const Q: Self = 0x9e3779b9u32;

    const BYTES: usize = 8usize;

    fn from_u8(val: u8) -> Self {
        val as u32
    }

    fn from_usize(val: usize) -> Self {
        val as u32
    }
}

//
// Encryption
// A = A + S[0]
// B = B + S[1]
// for i = 1 to 2 * (r + 1):
//     A = ((A ^ B) << B) + S[2 * i]
//     B = ((B ^ A) << A) + S[2 * i + 1]
//
pub fn encrypt<W: Word>(pt: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    // TODO: extend key
    let t = 2 * (rounds + 1);
    let s = vec![W::ZERO; t];

    let [mut a, mut b] = pt;

    a = a.wrapping_add(&s[0]);
    b = b.wrapping_add(&s[1]);
    for i in 1..rounds {
        a = rotl(a ^ b, b).wrapping_add(&s[2 * i]);
        b = rotl(b ^ a, a).wrapping_add(&s[2 * i + 1]);
    }
    [a, b]
}

//
// Decryption
// for i = 2 * (r + 1) to 1:
//     B = (B - S[2 * i + 1] >> A) ^ A
//     A = (A - S[2 * i] >> B) ^ B
// B = B - S[1]
// A = A - S[0]
//
pub fn decrypt<W: Word>(ct: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    // TODO: extend key
    let t = 2 * (rounds + 1);
    let s = vec![W::ZERO; t];

    let [mut a, mut b] = ct;

    for i in (1..rounds).rev() {
        b = rotr(b.wrapping_sub(&s[2 * i + 1]), a) ^ a;
        a = rotr(a.wrapping_sub(&s[2 * i]), b) ^ b;
    }
    [a.wrapping_sub(&s[0]), b.wrapping_sub(&s[1])]
}

//
// w: word lengths in bytes
// r: encryption/decryption rounds
// b: original key length in bytes
//
// 1. Transform the original key in an array of words L
//    array of bytes (u8) -> array of Words (u8, u16, u32, .., u128)
//
// key = 0x01 0x02 0x03 0x04 0x05
// Word = u32 -> w = 4
// L = [0x01020304, 0x05000000]
//
// c = max(1, ceil(8*b/w))
// for i = b-1 to 0:
//     L[i/w] = (L[i/w] << 8) + key[i]
//
// 0x01 + Word: u32 -> 0x01000000
//
// 2. Initialize an array S
//
// S[0] = P
// for i = 1 to t-1:
//     S[i] = S[i-1] + Q
//
// 3. Mix S and L
// i = j = 0
// A = B = 0
// do 3 * max(t,c) times:
//    A = S[i] = (S[i] + A + B) << 3
//    B = L[j] = (L[j] + A + B) << (A + B)
//    i = (i + j) mod t
//    j = (i + j) mod c
//
// Word: u8 0x49 + 0xfd =?
// input: key: Vec<u8>
// output: S: Vec<W>
pub fn expand_key<W: Word>(key: Vec<u8>, rounds: usize) -> Vec<W> {
    let b = key.len();
    let w = W::BYTES;
    let t = 2 * (rounds + 1);

    // ceil(8*b/w) = (8 * b + (w - 1)) / w
    let tmp = (8 * b + (w - 1)) / w;
    let c = std::cmp::max(1, tmp);
    let mut key_l = vec![W::ZERO; c];

    for i in (0..(b - 1)).rev() {
        let ix = i / w;
        key_l[ix] = rotl(key_l[ix], W::from_u8(8u8)).wrapping_add(&W::from_u8(key[i]));
    }

    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i - 1].wrapping_add(&W::Q);
    }

    // i = j = 0
    // A = B = 0
    // do 3 * max(t,c) times:
    //    A = S[i] = (S[i] + A + B) << 3
    //    B = L[j] = (L[j] + A + B) << (A + B)
    //    i = (i + j) mod t
    //    j = (i + j) mod c

    let mut i = 0usize;
    let mut j = 0usize;
    let mut a = W::ZERO;
    let mut b = W::ZERO;
    let iters = 3 * std::cmp::max(t, c);
    for _ in 0..iters {
        key_s[i] = rotl(key_s[i].wrapping_add(&a).wrapping_add(&b), W::from_u8(3u8));
        a = key_s[i];
        key_l[j] = rotl(key_l[j].wrapping_add(&a).wrapping_add(&b), a.wrapping_add(&b));
        b = key_s[j];
        i = (i + j) % t;
        j = (i + j) % c;
    }

    key_s
}

pub fn rotl<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x << a) | (x >> (W::from_usize(w) - a))
    }
}

pub fn rotr<W: Word>(x: W, y: W) -> W {
    let w = W::BYTES * 8;
    let a = y & W::from_usize(w - 1);
    if a == W::ZERO {
        x
    } else {
        (x >> a) | (x << (W::from_usize(w) - a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_right_shift() {
        let a = 0x77u8; // 0111 0111

        assert_eq!(rotl(a, 1u8), 0xeeu8);
        assert_eq!(rotl(a, 7u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotl(a, 8u8), a);
        assert_eq!(rotl(a, 2 * 8u8), a);
        assert_eq!(rotl(a, 5 * 8u8), a);

        assert_eq!(rotl(a, 1u8), 0xeeu8); // 1110 1110 = 0xee
        assert_eq!(rotl(a, 7u8), 0xbbu8); // 1011 1011 = 0xbb
        assert_eq!(rotr(a, 8u8), a);
        assert_eq!(rotr(a, 2 * 8u8), a);
        assert_eq!(rotr(a, 5 * 8u8), a);
    }

    #[test]
    fn test_rivest_1() {

        let key = vec![0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pt = [0x00000000u32, 0x00000000];//  ct = 0x21 a5 db ee 0x 15 4b 8f 6d
        let rounds = 12;

        let ct = encrypt(pt, key, rounds);
    }


}