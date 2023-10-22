mod ipv4;
mod ipv6;

//use std::io;
use regex::RegexSet;
use std::env;
use std::process::exit;

enum IpAddressVersion {
    IpV4,
    IpV6,
}

impl IpAddressVersion {
    fn get_address_version(input: &str) -> IpAddressVersion {
        let regex_seg = RegexSet::new(&[
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",        // Regex #0
            r"^([A-Fa-f0-9:]{1,4}:+)+([A-Fa-f0-9]{1,4})?$", // Regex #1
        ])
        .unwrap();

        match regex_seg
            .matches(input)
            .into_iter()
            .collect::<Vec<_>>()
            .as_slice()
        {
            [0] => IpAddressVersion::IpV4,
            [1] => IpAddressVersion::IpV6,
            _ => panic!("Invalid input format."),
        }
    }
}

fn print_help() {
    println!("\x1b[1m{}\x1b[0m", "IP Calculator in Rust - ipcrust");
    println!("https://github.com/pobradovic08/ipcrust");
    println!("Version {}", env!("CARGO_PKG_VERSION"));
    println!("2023, GPLv3");
    println!();
    println!("Usage: ipcrust [-h] NETWORK");
    println!("Arguments:");
    println!("    NETWORK\tIP address in CIDR notation or with mask");
    println!();
    println!("Options:");
    println!("    -h\t\tPrint this help");
    println!();
    println!(
        "{:16}\x1b[1m{}\x1b[0m",
        "Usage examples:", "ipcrust <ip>/<cidr>"
    );
    println!("{:16}\x1b[1m{}\x1b[0m", "", "ipcrust <ipv4>/<mask>");
    println!("{:16}\x1b[1m{}\x1b[0m", "", "ipcrust <ipv4> <mask>");
    println!("{:16}\x1b[1m{}\x1b[0m", "", "ipcrust <ip>");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut arguments: Vec<&str> = Vec::new();

    match args.len() {
        1 => {
            print_help();
            exit(1);
        }
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
        IpAddressVersion::IpV4 => match ipv4::Address::from_string(format!("{}/{}", arguments[0], arguments[1]).as_str()) {
            Ok(net) => ipv4::print_results(&net),
            Err(err) => {
                //TODO: display useful error message
                panic!("Invalid input: {:?}", err)
            }
        },
        IpAddressVersion::IpV6 => match ipv6::AddressV6::from_string(&args[1]) {
            Ok(net) => ipv6::print_results(&net),
            Err(err) => {
                //TODO: display useful error message
                panic!("Invalid input: {:?}", err)
            }
        },
    }
}
