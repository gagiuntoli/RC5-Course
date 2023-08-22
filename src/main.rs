fn main() {
    println!("Hello, world!");
}

pub trait Word:
    Clone
    + Copy
    + std::ops::AddAssign
    + std::ops::Add<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::Shl<Output = Self>
{
    const ZERO: Self;
}

//
// Encryption
// A = A + S[0]
// B = B + S[1]
// for i = 1 to 2 * (r + 1):
//     A = ((A ^ B) << B) + S[2 * i]
//     B = ((B ^ A) << A) + S[2 * i + 1]
//
pub fn encrypt<W: Word>(pt: [W; 2], rounds: usize) -> [W; 2] {
    // TODO: extend key
    let t = 2 * (rounds + 1);
    let s = vec![W::ZERO; t];

    let [mut a, mut b] = pt;

    a += s[0];
    b += s[1];
    for i in 0..t {
        a = ((a ^ b) << b) + s[2 * i];
        b = ((b ^ a) << a) + s[2 * i + 1];
    }
    [a, b]
}

//
// Decryption
// A = A + S[0]
// B = B + S[1]
// for i = 1 to 2 * (r + 1):
//     A = ((A ^ B) << B) + S[2 * i]
//     B = ((B ^ A) << A) + S[2 * i + 1]
//
