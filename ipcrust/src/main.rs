mod ipv6;
mod ipv4;

//use std::io;
use regex::RegexSet;

fn main() {
    let ip_string = String::from("fe80::02BB:CCFF:FEDD:1122/32");

    let parts: Vec<&str> = ip_string.split(|c| (c == ' ') || (c == '/')).collect();

    let ip_part = parts[0];
    let mask_part = parts[1];

    let regex_seg = RegexSet::new(&[
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",            // Regex #0
        r"^([A-Fa-f0-9:]{1,4}:+)+([A-Fa-f0-9]{1,4})?$"      // Regex #1
    ]).unwrap();

    match regex_seg.matches(ip_part).into_iter().collect::<Vec<_>>().as_slice() {
        [0] => {
            let ip: ipv4::Address;
            let mask: ipv4::Mask;

            ip = ipv4::Address::from_string(ip_part);

            match parts.len() {
                1 => mask = ipv4::Mask::from_cidr(ip.get_default_class_cidr()),
                2 => mask = {
                    match mask_part.parse::<u8>() {
                        Ok(v) => ipv4::Mask::from_cidr(v),
                        Err(_) => ipv4::Mask::from_dotted_decimal(mask_part)
                    }
                },
                _ => panic!("Invalid input format.")
            }

            let net = ipv4::Network::new(ip, mask);
            ipv4::print_results(&net);
        }
        [1] => {
            let ip: ipv6::Address;
            let net: ipv6::Network;
            let cidr: u8;

            ip = ipv6::Address::from_string(ip_part);
            cidr = mask_part.parse::<u8>().unwrap();

            net = ipv6::Network::new(ip, cidr);
            ipv6::print_results(&net);
        }
        _ => panic!("Invalid format")
    }
}