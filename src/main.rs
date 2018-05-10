// Based/Inspired by Jeff Erickson, "The Art of Exploitation"
extern crate docopt;
#[macro_use]
extern crate serde_derive;
use docopt::Docopt;
use std::{str, collections::HashMap};
const USAGE: &'static str = "
Stupid encoder, 32bits. Use EAX register, push the result to STACK.
Assumed: EAX = 0

Usage:
  stupid_encoder <payload> [--bytes <bytes>] [--start-value <start_value>]
  stupid_encoder (-h | --help)

Options:
  --bytes <bytes>, -b <bytes>                           Allowed bytes [default: \\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0b\\x0c\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c\\x2d\\x2e\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3b\\x3c\\x3d\\x3e\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5a\\x5b\\x5c\\x5d\\x5e\\x5f\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d\\x6e\\x6f\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b\\x7c\\x7d\\x7e\\x7f]
  --start-value <start_value>, -s <start_value>         Start value [default: \\x00\\x00\\x00\\x00]
  -h --help                                             Show this screen.
";
const PUSH_EAX: u8 = 0x50;
const ADD_EAX: u8 = 0x05;
const SUB_EAX: u8 = 0x2D;
#[derive(Deserialize)]
struct Args {
    arg_payload: String,
    flag_bytes: String,
    flag_start_value: String,
}
fn can_encode(good_bytes: &Vec<u8>) -> bool {
    if !good_bytes.contains(&PUSH_EAX)
        || (!good_bytes.contains(&SUB_EAX) && !good_bytes.contains(&ADD_EAX))
    {
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

fn compose(value: Vec<u8>) -> u32 {
    let mut result = 0;
    for i in 0..4 {
        result += (value[i] as u32) << i * 8;
    }
    result
}

// Don't look, it's ugly.
fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let good_bytes = parse_bytes(&args.flag_bytes);
    if !can_encode(&good_bytes) {
        panic!("Can't encode");
    }
    let payload = parse_bytes(&args.arg_payload);
    let mut previous = compose(parse_bytes(&args.flag_start_value));
    println!("encoded_egghunter=(");
    for chunk in payload.chunks(4).rev() {
        let wanted = compose(chunk.to_vec());
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
    is_sub: bool,
) -> Option<u8> {
    let shot;
    let single_compare;
    if is_sub {
        shot = target_byte as u32 + carry as u32
            + bytes
                .iter()
                .fold(0u32, |total, next| total + next.unwrap_or(0) as u32);
        single_compare = initial_byte;
    } else {
        shot = initial_byte as u32 + carry as u32
            + bytes
                .iter()
                .fold(0u32, |total, next| total + next.unwrap_or(0) as u32);
        single_compare = target_byte;
    }
    let single = (shot & 0xff) as u8;
    if single == single_compare {
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
    let is_sub = good_bytes.contains(&SUB_EAX);
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
                                    is_sub,
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
                                is_sub,
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
                        is_sub,
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
                is_sub,
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
                if !good_bytes.contains(&SUB_EAX) {
                    print!("\"\\x{:01$x}", ADD_EAX, 2);
                } else {
                    print!("\"\\x{:01$x}", SUB_EAX, 2);
                }
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
