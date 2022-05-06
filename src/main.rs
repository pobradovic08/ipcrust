use std::io;
use regex::{Regex, Captures};
use clap::{arg, Command};
use ansi_term;

const MAX_EXPONENT: usize = 5;

///
/// Convert absolute number to base number and exponent.
///
/// Exponent is used to find appropriate unit:
/// 1 - kilo, 2 - mega, 3 - giga, etc.
///
fn normalize_units(value: f64, exponent: usize) -> (f64, usize) {
    if exponent > MAX_EXPONENT {
        panic!("Provided value is too large");
    }

    if value <= 0.0 {
        panic!("Provided value must be greater than 0");
    }

    if value >= 1024.0 {
        return normalize_units(value / 1024.0, exponent + 1);
    }
    (value, exponent)
}

///
/// Return bps with SI prefix based on passed `exponent` value
///
fn print_units(input: (f64, usize), unit: &str) -> String {
    let prefix = ["b", "k", "m", "g", "t", "p"];
    let (value, exponent) = input;
    if exponent > MAX_EXPONENT {
        panic!("Provided value is too large");
    }
    format!("{:7.2} {}{}", value, prefix[exponent], unit)
}

///
/// Parse input and return base value and exponent
/// Input value should be in format: `1234mpps`
/// Examples:
/// `1234pps`, `123kpps`, `12mpps`, `60gbps`
///
fn parse_units(input: &str) -> (f64, usize) {
    let units = ["k", "m", "g", "t", "p"];
    let mat: Captures;
    let value: f64;
    let exponent: usize;

    // Build regex for matching input argument
    let re = Regex::new(r"^(\d+)([kmgtp])?pps(\s)?$").unwrap();


    // Capture regex groups from input string
    match re.captures(input) {
        Some(v) => mat = v,
        None => panic!("Format must be in '[0-9]+[kmgtp]pps'"),
    }

    // Fetch and parse base value as f64
    match mat.get(1).unwrap().as_str().parse::<f64>() {
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

    // Return (value, exponent) tuple
    (value, exponent)
}

///
/// Calculate bandwidth (bps) for given pps value
///
fn to_bps(pps: f64, packet_size: i32) -> f64{
    pps * packet_size as f64 * 8.0
}

///
/// Calculate usable bandwidth coefficient based on provided overhead value.
/// Overhead value is given in addition to standard ethernet 20B overhead.
///
fn get_efficiency(packet_size: i32, overhead: i32) -> f64 {
    packet_size as f64 / (packet_size + overhead + 20) as f64
}

fn print_bps_results(pps: f64, exponent: usize, packet_size: i32) {

    let underline = ansi_term::Style::new().underline();

    // Typical packet sizes
    let mut sizes = vec![64, 594, 1518];
    if !sizes.contains(&packet_size) {
        sizes.push(packet_size);
        sizes.sort();
    }

    /*
    Add packet size corresponding to average Simple IMIX packet size.
    Simple IMIX:
      64 B x 7 packets =  448 B
     594 B x 4 packets = 2376 B
    1518 B x 1 packets = 1518 B
    -------------------
            12 packets = 4342 B => ~362 B / packet
     */
    sizes.push(362);

    // Tuples with overhead in bytes for most common encapsulations
    let overheads = [
        ("VLAN", 4), ("QinQ", 8), ("VXLAN", 50),
        ("MPLS", 4), ("PPPoE", 8), ("GRE", 4)
    ];


    println!("{:=^60}\n", "[ Packets Per Second Calculator ]");

    println!("Input PPS:  \x1b[1;92m{}\x1b[0m", print_units((pps, exponent), "pps"));
    println!("Packet size: \x1b[1;92m{} B\x1b[0m\n", packet_size);

    // Throughput section header
    println!("{:<23}{:<28}{:<28}\x1b[0m",
             format!("{}", underline.paint("Packet size:")),
             format!("{}", underline.paint("Throughput:")),
             format!("{}", underline.paint("With overhead*:"))
    );

    // Iterate over packet sizes vector and calculate values for each size
    for (i, p_size) in sizes.iter().enumerate() {

        let normalized = normalize_units(to_bps(pps, *p_size), exponent);
        let efficiency = get_efficiency(*p_size, 0);
        let normalized_o = normalize_units(to_bps(pps * efficiency, *p_size), exponent);

        // Color last row (IMIX traffic) result
        if i == sizes.len() - 1 { print!("\x1b[1;96m"); }

        println!("{}{:<15}{:<20}{:<20}\x1b[0m",
                 // Color user selected packet size row
                 if *p_size == packet_size { "\x1b[1m\x1b[97m" } else { "" }, //Color user selected packet size
                 // Print text description for IMIX instead of packet size
                 if i == sizes.len() - 1 { format!("{}", "Simple IMIX") } else { format!("{:5} B", p_size) },
                 print_units(normalized, "bps"),
                 format!("{} ({:.2}%)", print_units(normalized_o, "bps"), efficiency * 100.0)
        );
    }

    println!("\n\nApproximate theoretical ethernet throughputs with common\nencapsulations overheads:\n");

    // Overhead section header
    println!("{:<23}{:<28}{:<28}\x1b[0m",
             format!("{}", underline.paint("Encap:")),
             format!("{}", underline.paint("Overhead:")),
             format!("{}", underline.paint("With overhead*:"))
    );

    for (tech, overhead) in overheads {
        let efficiency = get_efficiency(packet_size, overhead);
        let normalized_o = normalize_units(to_bps(pps * efficiency, packet_size), exponent);
        println!("{:<15}{:<20}{:<20}\x1b[0m",
                 tech, format!("{:3} B", overhead),
                 format!("{} ({:.2}%)", print_units(normalized_o, "bps"), efficiency * 100.0)
        );
    }

    println!("\n\n* These are just approximations\n  and are \x1b[1;97mnot\x1b[0m accurate calculations.");

    println!("\n{:=^60}", "");
}

fn main() -> io::Result<()> {
    let arguments = Command::new("Packets Per Second calculator")
        .version("0.2")
        .author("Pavle Obradovic <pobradovic08@gmail.com>")
        .about("Converts PPS value to maximum theoretical throughput.")
        .arg(arg!(<pps> "Packets Per Second in [pps, kpps, mpps, ...]"))
        .arg(arg!(-s --size [packet_size] "Packet size in bytes").default_value("64"))
        .get_matches();

    let pps_input: &str;
    let packet_size: i32;

    match arguments.value_of("pps") {
        Some(v) => pps_input = v,
        None => panic!("Error parsing pps value"),
    }

    match arguments.value_of("size") {
        Some(v) => match v.parse::<i32>() {
            Ok(v) => match v {
                64..=65536 => packet_size= v,
                _ => panic!("Packet size must be between 64B and 64KB (65536B)")
            },
            Err(_) => packet_size = 64,
        },
        None => packet_size = 64,
    }

    let (pps, exponent) = parse_units(pps_input);
    print_bps_results(pps, exponent, packet_size);

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_normalization() {
        assert_eq!(normalize_units(1.0, 0), (1.0, 0));
        assert_eq!(normalize_units(1023.0, 0), (1023.0, 0));
        assert_eq!(normalize_units(1024.0, 0), (1.0, 1));
    }

    #[test]
    #[should_panic]
    fn test_unit_normalization_out_of_bounds() {
        normalize_units(1024.0, 5);
    }

    #[test]
    #[should_panic]
    fn test_unit_normalization_zero() {
        normalize_units(0.0, 0);
    }

    #[test]
    #[should_panic]
    fn test_unit_normalization_negative() {
        normalize_units(-1.0, 0);
    }

    #[test]
    fn test_print_units() {
        assert_eq!(print_units((1.0, 0), "bps"), "   1.00 bps");
        assert_eq!(print_units((512.0, 0), "bps"), " 512.00 bps");
        assert_eq!(print_units((1023.0, 0), "bps"), "1023.00 bps");

        assert_eq!(print_units((0.001, 0), "bps"), "   0.00 bps");
        assert_eq!(print_units((1023.1234, 0), "bps"), "1023.12 bps");
        assert_eq!(print_units((1023.99, 0), "bps"), "1023.99 bps");
        assert_eq!(print_units((1023.9999, 0), "bps"), "1024.00 bps");

        assert_eq!(print_units((1.0, 0), "bps"), "   1.00 bps");
        assert_eq!(print_units((1.0, 0), "bps"), "   1.00 bps");
        assert_eq!(print_units((1.0, 1), "bps"), "   1.00 kbps");
        assert_eq!(print_units((1.0, 2), "bps"), "   1.00 mbps");
        assert_eq!(print_units((1.0, 3), "bps"), "   1.00 gbps");
        assert_eq!(print_units((1.0, 4), "bps"), "   1.00 tbps");
        assert_eq!(print_units((1.0, 5), "bps"), "   1.00 pbps");
    }

    #[test]
    #[should_panic]
    fn test_print_units_out_of_bounds() {
        print_units((1.0, 6), "bps");
    }
}