extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate rand;
use docopt::Docopt;
use rand::{thread_rng, Rng};
use std::{str, collections::HashMap};
const USAGE: &'static str = "
Stupid encoder, 32bits. Use EAX register, push the result to STACK.
Assumed: EAX = 0

Usage:
  stupid_encoder <payload> <bytes>
  stupid_encoder (-h | --help)

Options:
  -h --help                                     Show this screen.
";
const PUSH_EAX: u8 = 0x50;
const SUB_EAX: u8 = 0x2D;
#[derive(Deserialize)]
struct Args {
    arg_payload: String,
    arg_bytes: String,
}
fn can_encode(good_bytes: &Vec<u8>) -> bool {
    if !good_bytes.contains(&PUSH_EAX) || !good_bytes.contains(&SUB_EAX) {
        return false;
    }
    true
}

fn parse_bytes(arg: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for byte in arg.split("\\x") {
        if byte.is_empty() {
            continue;
        }
        result.push(u8::from_str_radix(&byte, 16).expect(&format!(
            "Not an hexadecimal string: {}. Expect something like 'FF'",
            &byte
        )));
    }
    result
}

fn decompose(value: u32) -> Vec<u8> {
    let mut result = Vec::new();
    for i in 0..4 {
        result.push(decompose_shift(value, i * 8))
    }
    result
}

fn decompose_shift(value: u32, shift: u8) -> u8 {
    ((value & (0xFF << shift)) >> shift) as u8
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let mut good_bytes = parse_bytes(&args.arg_bytes);
    if !can_encode(&good_bytes) {
        panic!("Can't encode");
    }
    thread_rng().shuffle(&mut good_bytes);
    let payload = parse_bytes(&args.arg_payload);
    let mut previous: u32 = 0;
    println!("encoded_egghunter=(");
    for chunk in payload.chunks(4).rev() {
        let wanted: u32 = ((chunk[3] as u32) << 24) + ((chunk[2] as u32) << 16)
            + ((chunk[1] as u32) << 8) + (chunk[0] as u32);
        generate(previous, wanted, &good_bytes);
        previous = wanted;
    }
    println!(")");
}

fn generate_instruction_byte(
    bytes: Vec<Option<u8>>,
    carry: u8,
    byte_number: usize,
    word: &mut HashMap<usize, HashMap<usize, u8>>,
    target_byte: u8,
    initial_byte: u8,
) -> Option<u8> {
    let shot: u32 = target_byte as u32 + carry as u32
        + bytes
            .iter()
            .fold(0u32, |total, next| total + next.unwrap_or(0) as u32);
    let single = (shot & 0xff) as u8;
    if single == initial_byte {
        let carry = ((shot & (0xff << 8)) >> 8) as u8;
        for byte_count in 0..4 {
            match bytes[byte_count] {
                Some(byte) => {
                    word.entry(byte_count)
                        .or_insert(HashMap::new())
                        .insert(byte_number, byte);
                }
                None => {}
            }
        }
        return Some(carry);
    }
    None
}

fn generate_instruction_byte_number(
    instruction_count: u8,
    good_bytes: &Vec<u8>,
    word: &mut HashMap<usize, HashMap<usize, u8>>,
    target_bytes: &Vec<u8>,
    initial_bytes: &Vec<u8>,
    carry: u8,
    byte_number: usize,
) -> Option<u8> {
    for good_byte1 in good_bytes {
        if instruction_count > 1 {
            for good_byte2 in good_bytes {
                if instruction_count > 2 {
                    for good_byte3 in good_bytes {
                        if instruction_count > 3 {
                            for good_byte4 in good_bytes {
                                let carry_result = generate_instruction_byte(
                                    vec![
                                        Some(*good_byte1),
                                        Some(*good_byte2),
                                        Some(*good_byte3),
                                        Some(*good_byte4),
                                    ],
                                    carry,
                                    byte_number,
                                    word,
                                    target_bytes[byte_number],
                                    initial_bytes[byte_number],
                                );
                                if carry_result.is_some() {
                                    return carry_result;
                                }
                            }
                        } else {
                            let carry_result = generate_instruction_byte(
                                vec![
                                    Some(*good_byte1),
                                    Some(*good_byte2),
                                    Some(*good_byte3),
                                    None,
                                ],
                                carry,
                                byte_number,
                                word,
                                target_bytes[byte_number],
                                initial_bytes[byte_number],
                            );
                            if carry_result.is_some() {
                                return carry_result;
                            }
                        }
                    }
                } else {
                    let carry_result = generate_instruction_byte(
                        vec![Some(*good_byte1), Some(*good_byte2), None, None],
                        carry,
                        byte_number,
                        word,
                        target_bytes[byte_number],
                        initial_bytes[byte_number],
                    );
                    if carry_result.is_some() {
                        return carry_result;
                    }
                }
            }
        } else {
            let carry_result = generate_instruction_byte(
                vec![Some(*good_byte1), None, None, None],
                carry,
                byte_number,
                word,
                target_bytes[byte_number],
                initial_bytes[byte_number],
            );
            if carry_result.is_some() {
                return carry_result;
            }
        }
    }
    None
}

fn generate_instruction(
    instruction_count: u8,
    good_bytes: &Vec<u8>,
    word: &mut HashMap<usize, HashMap<usize, u8>>,
    target_bytes: &Vec<u8>,
    initial_bytes: &Vec<u8>,
) -> bool {
    let mut carry: u8 = 0;
    let mut flag: u8 = 0;
    for byte_number in 0..4 {
        match generate_instruction_byte_number(
            instruction_count,
            good_bytes,
            word,
            target_bytes,
            initial_bytes,
            carry,
            byte_number,
        ) {
            Some(c) => {
                carry = c;
                flag += 1;
            }
            None => {}
        };
    }
    return flag == 4;
}

fn generate(initial: u32, target: u32, good_bytes: &Vec<u8>) {
    let target_bytes = decompose(target);
    let initial_bytes = decompose(initial);
    let mut word: HashMap<usize, HashMap<usize, u8>> = HashMap::new();
    for instruction_count in 1..5 {
        if generate_instruction(
            instruction_count,
            &good_bytes,
            &mut word,
            &target_bytes,
            &initial_bytes,
        ) {
            for instruction_index in 0..5 {
                if !word.get(&instruction_index).is_some() {
                    break;
                }
                print!("\"\\x{:01$x}", SUB_EAX, 2);
                print!("\\x{:01$x}", word[&instruction_index][&0], 2);
                print!("\\x{:01$x}", word[&instruction_index][&1], 2);
                print!("\\x{:01$x}", word[&instruction_index][&2], 2);
                print!("\\x{:01$x}", word[&instruction_index][&3], 2);
                println!("\"");
            }
            println!("\"\\x{:01$x}\"", PUSH_EAX, 2);
            return;
        }
    }
    panic!("Failed to encode");
}
