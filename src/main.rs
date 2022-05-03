use std::io;
use regex::Regex;

fn strip(input: &str) -> &str {
    input.strip_suffix("\r\n").or(input.strip_suffix("\n")).unwrap_or(input)
}

fn normalize_units(value: f64, exponent: usize) -> (f64, usize) {
    if value >= 1024.0 {
        return normalize_units(value/1024.0, exponent + 1);
    }
    (value, exponent)
}

fn print_units(input: (f64, usize)) -> String {
    let units = ["bps", "kbps", "mbps", "gbps", "tbps", "pbps"];
    let (value, exponent) = input;
    format!("{:7.2} {}", value, units[exponent])
}

fn parse_units(input: &str) -> (i64, usize) {
    let units = ["k", "m", "g", "t", "p"];

    let re = Regex::new(r"^(\d+)\s*([kmgtp])?([pb])ps(\s)?$").unwrap();
    let mat = re.captures(input).unwrap();

    let value: i64;
    match mat.get(1).unwrap().as_str().parse::<i64>() {
        Ok(v) => value = v,
        Err(e) => panic!("{}", e),
    }

    let exponent: usize;
    match mat.get(2) {
        Some(v) => {
            let index = units.iter().position(|&r| r == v.as_str()).unwrap();
            exponent = index + 1;
        },
        None => exponent = 0,
    }

    (value, exponent)
}

fn main() -> io::Result<()> {

    /// Multiply packets per second with packet size (in bits) to get base bps
    let to_bps = |pps: i64, packet_size: i64| pps * packet_size * 8;

    let mut line = String::new();
    println!("Input PPS:");
    io::stdin().read_line(&mut line).unwrap();

    let (pps, exponent) = parse_units(&line);
    println!("Input: {} ^ {}", pps, exponent);


    for packet_size in [64, 578, 1500] {
        println!("{} for {:4}B packets",
                 print_units(normalize_units(to_bps(pps, packet_size) as f64, exponent)),
                 packet_size);
    }

    Ok(())
}
