// Based/Inspired by Jeff Erickson, "The Art of Exploitation"
use clap::Parser;
use std::{collections::HashMap, str};

#[derive(Parser)]
#[clap(version = clap::crate_version!(), author = clap::crate_authors!())]
struct Opts {
    #[clap(short, long, default_value = "\\x00\\x00\\x00\\x00")]
    start_value: String,

    #[clap(short, long, conflicts_with = "good_bytes")]
    bad_bytes: Option<String>,

    #[clap(short, long, conflicts_with = "bad_bytes")]
    good_bytes: Option<String>,

    payload: String,
}

const PUSH_EAX: u8 = 0x50;
const ADD_EAX: u8 = 0x05;
const SUB_EAX: u8 = 0x2D;

fn can_encode(good_bytes: &[u8]) -> bool {
    good_bytes.contains(&PUSH_EAX)
        && (good_bytes.contains(&SUB_EAX) || good_bytes.contains(&ADD_EAX))
}

fn parse_bytes(arg: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for byte in arg.split("\\x") {
        if byte.is_empty() {
            continue;
        }
        result.push(u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
            panic!(
                "Not an hexadecimal string: {}. Expect something like 'FF'",
                &byte
            )
        }));
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

const fn decompose_shift(value: u32, shift: u8) -> u8 {
    ((value & (0xFF << shift)) >> shift) as u8
}

fn compose(value: &[u8]) -> u32 {
    let mut result = 0;
    for (i, v) in value.iter().enumerate().take(4) {
        result += u32::from(*v) << (i * 8);
    }
    result
}

fn main() {
    let opts: Opts = Opts::parse();
    let mut good_bytes = Vec::new();
    if let Some(good_bytes_raw) = opts.good_bytes {
        good_bytes = parse_bytes(&good_bytes_raw);
    }
    if let Some(bad_bytes_raw) = opts.bad_bytes {
        let bad_bytes = parse_bytes(&bad_bytes_raw);
        for i in u8::min_value()..=u8::max_value() {
            if !bad_bytes.contains(&i) {
                good_bytes.push(i);
            }
        }
    }
    if !can_encode(&good_bytes) {
        panic!("Can't encode");
    }
    let payload = parse_bytes(&opts.payload);
    let mut previous = compose(&parse_bytes(&opts.start_value));
    println!("payload=(");
    for chunk in payload.chunks(4).rev() {
        let wanted = compose(chunk);
        generate(previous, wanted, &good_bytes);
        previous = wanted;
    }
    println!(")");
}

fn generate_instruction_byte(
    instruction_count: u8,
    deep: u8,
    good_bytes: &[u8],
    word: &mut HashMap<usize, HashMap<usize, u8>>,
    target_bytes: &[u8],
    initial_bytes: &[u8],
    carry: u8,
    byte_number: usize,
    is_sub: bool,
    bytes: &mut Vec<Option<u8>>,
) -> Option<u8> {
    for good_byte in good_bytes {
        bytes[deep as usize] = Some(*good_byte);
        if instruction_count - deep > 1 {
            let result = generate_instruction_byte(
                instruction_count,
                deep + 1,
                good_bytes,
                word,
                target_bytes,
                initial_bytes,
                carry,
                byte_number,
                is_sub,
                bytes,
            );
            if result.is_some() {
                return result;
            }
        } else {
            let mut shot = u32::from(carry)
                + bytes
                    .iter()
                    .fold(0_u32, |total, next| total + u32::from(next.unwrap_or(0)));
            let single_compare = if is_sub {
                shot += u32::from(target_bytes[byte_number]);
                initial_bytes[byte_number]
            } else {
                shot += u32::from(initial_bytes[byte_number]);
                target_bytes[byte_number]
            };
            if (shot & 0xff) as u8 == single_compare {
                let carry = ((shot & (0xff << 8)) >> 8) as u8;
                for (byte_count, maybe_byte) in bytes.iter().enumerate().take(4) {
                    if let Some(byte) = maybe_byte {
                        word.entry(byte_count)
                            .or_insert_with(HashMap::new)
                            .insert(byte_number, *byte);
                    }
                }
                return Some(carry);
            }
        }
    }
    None
}
fn generate_instruction(
    instruction_count: u8,
    good_bytes: &[u8],
    word: &mut HashMap<usize, HashMap<usize, u8>>,
    target_bytes: &[u8],
    initial_bytes: &[u8],
) -> bool {
    let mut carry: u8 = 0;
    let mut flag: u8 = 0;
    let is_sub = good_bytes.contains(&SUB_EAX);
    for byte_number in 0..4 {
        if let Some(c) = generate_instruction_byte(
            instruction_count,
            0,
            good_bytes,
            word,
            target_bytes,
            initial_bytes,
            carry,
            byte_number,
            is_sub,
            &mut vec![None, None, None, None],
        ) {
            carry = c;
            flag += 1;
        };
    }
    flag == 4
}

fn generate(initial: u32, target: u32, good_bytes: &[u8]) {
    let target_bytes = decompose(target);
    let initial_bytes = decompose(initial);
    let mut word: HashMap<usize, HashMap<usize, u8>> = HashMap::new();
    for instruction_count in 1..5 {
        if generate_instruction(
            instruction_count,
            good_bytes,
            &mut word,
            &target_bytes,
            &initial_bytes,
        ) {
            for instruction_index in 0..5 {
                if word.get(&instruction_index).is_none() {
                    break;
                }
                if good_bytes.contains(&SUB_EAX) {
                    print!("b\"\\x{:01$x}", SUB_EAX, 2);
                } else {
                    print!("b\"\\x{:01$x}", ADD_EAX, 2);
                }
                for index in 0..4 {
                    print!("\\x{:01$x}", word[&instruction_index][&index], 2);
                }
                println!("\"");
            }
            println!("b\"\\x{:01$x}\"", PUSH_EAX, 2);
            return;
        }
    }
    panic!("Failed to encode");
}
