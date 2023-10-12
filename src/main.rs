mod ipv6;
mod ipv4;

//use std::io;
use regex::RegexSet;
use std::env;

enum IpAddressVersion {
    IpV4,
    IpV6
}

impl IpAddressVersion {
    fn get_address_version(input: &str) -> IpAddressVersion {
        let regex_seg = RegexSet::new(&[
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",            // Regex #0
            r"^([A-Fa-f0-9:]{1,4}:+)+([A-Fa-f0-9]{1,4})?$"      // Regex #1
        ]).unwrap();

        match regex_seg.matches(input).into_iter().collect::<Vec<_>>().as_slice() {
            [0] => IpAddressVersion::IpV4,
            [1] => IpAddressVersion::IpV6,
            _ => panic!("Invalid input format.")
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut arguments: Vec<&str> = Vec::new();

    match args.len() {
        2 => {
            let ip_str = &args[1];
            let parts: Vec<&str> = ip_str.split(|c| c == '/').collect();
            match parts.len() {
                1 => {
                    arguments.insert(0, parts[0]);
                }
                2 => {
                    arguments.insert(0, parts[0]);
                    arguments.insert(1, parts[1]);
                }
                _ => {
                    panic!("Invalid input format.");
                }
            }
        }
        3 => {
            arguments.insert(0, args[1].as_str());
            arguments.insert(1, args[2].as_str());
        }
        _ => {
            panic!("Invalid number of arguments.");
        }
    }

    match IpAddressVersion::get_address_version(arguments[0]) {
        IpAddressVersion::IpV4 => {
            let ip: ipv4::Address;
            let mask: ipv4::Mask;

            ip = ipv4::Address::from_string(arguments[0]);

            match arguments.len() {
                1 => mask = ipv4::Mask::from_cidr(ip.get_default_class_cidr()),
                2 => mask = {
                    match arguments[1].parse::<u8>() {
                        Ok(v) => ipv4::Mask::from_cidr(v),
                        Err(_) => ipv4::Mask::from_dotted_decimal(arguments[1])
                    }
                },
                _ => panic!("Invalid input format.")
            }

            let net = ipv4::Network::new(ip, mask);
            ipv4::print_results(&net);
        }
        IpAddressVersion::IpV6 => {
            let ip: ipv6::AddressV6;
            let net: ipv6::NetworkV6;
            let cidr: u8;

            if arguments.len() == 1 {
                arguments.insert(1, "64");
            }

            ip = ipv6::AddressV6::from_string(arguments[0]);
            cidr = arguments[1].parse::<u8>().unwrap();

            net = ipv6::NetworkV6::new(ip, cidr);
            ipv6::print_results(&net);
        }
    }
}