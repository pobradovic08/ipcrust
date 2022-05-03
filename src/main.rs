use std::io;
use std::io::Write;
use regex::{Regex, Captures};
use log::{debug};

///
/// Convert absolute number to base number and exponent.
///
/// Exponent is used to find appropriate unit:
/// 1 - kilo, 2 - mega, 3 - giga, etc.
///
fn normalize_units(value: f64, exponent: usize) -> (f64, usize) {
    if value >= 1024.0 {
        return normalize_units(value / 1024.0, exponent + 1);
    }
    (value, exponent)
}

///
/// Return bps with SI prefix based on passed `exponent` value
///
fn print_units(input: (f64, usize)) -> String {
    let units = ["bps", "kbps", "mbps", "gbps", "tbps", "pbps"];
    let (value, exponent) = input;
    format!("{:7.2} {}", value, units[exponent])
}

///
/// Parse input and return base value and exponent
/// Input value should be in format: `1234 mpps`
/// Examples:
/// `1234 pps`, `123 kpps`, `12 mpps`, `60 gbps`
///
fn parse_units(input: &str) -> (i64, usize) {
    let units = ["k", "m", "g", "t", "p"];
    let mat: Captures;
    let value: i64;
    let exponent: usize;

    // Build regex for matching input argument
    let re = Regex::new(r"^(\d+)\s*([kmgtp])?([pb])ps(\s)?$").unwrap();


    // Capture regex groups from input string
    match re.captures(input) {
        Some(v) => mat = v,
        None => panic!("Format must be in '[0-9]+ [kmgtp]bps'"),
    }

    // Fetch and parse base value as f64
    match mat.get(1).unwrap().as_str().parse::<i64>() {
        Ok(v) => value = v,
        Err(_) => panic!("Can't parse input value as float."),
    }

    // Fetch optional unit value and set appropriate exponent
    match mat.get(2) {
        Some(v) => {
            let index = units.iter().position(|&r| r == v.as_str()).unwrap();
            exponent = index + 1;
        }
        None => exponent = 0,
    }

    //TODO: differentiate and convert between pps and kbs, based on input

    // Return (value, exponent) tuple
    (value, exponent)
}

fn help() {
    println!("Convert PPS to BPS.
Usage examples:
    > pps-calc 15 mpps
    > pps-calc 125000 pps")
}

fn main() -> io::Result<()> {

    // Multiply packets per second with packet size (in bits) to get base bps
    let to_bps = |pps: i64, packet_size: i64| pps * packet_size * 8;

    // String buffer for user input
    let mut line = String::new();

    // Read user input
    // TODO: move to argv
    print!("Input PPS: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut line).unwrap();

    // Parse user input
    let (pps, exponent) = parse_units(&line);

    // Print maximum bps for multiple packet sizes
    for packet_size in [64, 578, 1500] {
        println!("{} for {:4}B packets",
                 print_units(normalize_units(to_bps(pps, packet_size) as f64, exponent)),
                 packet_size);
    }

    Ok(())
}
