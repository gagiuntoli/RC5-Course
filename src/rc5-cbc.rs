/*
  cargo run rc5-cbc -- [--enc/--dec] <input-path> <output-path> <secret-key>
*/

use std::env;
use std::fs;

enum Actions {
    Encrypt,
    Decrypt,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    dbg!(&args);

    let option = match args[3].as_str() {
        "--enc" => Actions::Encrypt,
        "--dec" => Actions::Decrypt,
        _ => panic!("Bad argument as action, provide [--enc/--dec]"),
    };

    let input = args[4].as_str();
    let output = args[5].as_str();
    let key = args[6].as_bytes();

    let input = fs::read(input).expect(&format!("File {} couldn't be read", input));

    // TODO: encrypt/decrypt

    fs::write(output, input);
}
