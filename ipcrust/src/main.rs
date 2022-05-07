extern crate core;

use std::fmt::{Display, Formatter};
use std::io;
use regex::Regex;

fn int_to_dotted_decimal(integer: &u32) -> String {
    format!("{}.{}.{}.{}",
             integer >> 24,
             (integer >> 16) & 0xff,
             (integer >> 8) & 0xff,
             integer & 0xff,
    )
}

fn int_to_cidr(val: &u32, cidr: u8) -> u8 {
    if val == &0 {
        return cidr;
    }
    int_to_cidr(&(val << 1), cidr + 1)
}

fn dotted_decimal_to_int(address_string: &str) -> u32 {
    let regex_dotted_decimal = Regex::new(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$").unwrap();

    match regex_dotted_decimal.captures(&address_string) {
        Some(v) => {
            let raw_ip_parts = [
                v.get(1).unwrap().as_str(),
                v.get(2).unwrap().as_str(),
                v.get(3).unwrap().as_str(),
                v.get(4).unwrap().as_str()
            ];

            let ip_parts: [u32; 4] = raw_ip_parts.map(
                |value| value.parse::<u32>().unwrap()
            );

            let mut int_ip = ip_parts[0] << 24;
            int_ip += ip_parts[1] << 16;
            int_ip += ip_parts[2] << 8;
            int_ip += ip_parts[3];

            return int_ip;
        }
        None => panic!("Not an IPv4 Address")
    }
}

struct IPv4Address {
    address: u32,
}

struct IPv4Mask {
    address: u32,
}

impl IPv4Address {
    fn from_string(address_string: &str) -> IPv4Address {
        IPv4Address{address: dotted_decimal_to_int(address_string)}
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }


}

impl IPv4Mask {

    fn from_dotted_decimal(address_string: &str) -> IPv4Mask {
        IPv4Mask{address: dotted_decimal_to_int(address_string)}
    }

    fn from_cidr(cidr: u8) -> IPv4Mask {
        IPv4Mask{address: u32::MAX << (32 - cidr)}
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    fn to_cidr(&self) -> u8 {
        int_to_cidr(&self.address, 0)
    }

}

impl Display for IPv4Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

struct IPv4Network {
    ip: IPv4Address,
    mask: IPv4Mask,
    network: IPv4Address,
    broadcast: IPv4Address,
}

impl IPv4Network {
    fn new(ip: IPv4Address, mask_option: Option<IPv4Mask>) -> IPv4Network {
        let mask: IPv4Mask;

        match mask_option {
            Some(v) => mask = v,
            None => mask = IPv4Mask { address: 124 }
        }

        let network = IPv4Address { address: ip.address & mask.address };
        let broadcast = IPv4Address { address: network.address | (u32::MAX >> mask.to_cidr()) };

        IPv4Network { ip, mask, network, broadcast }
    }
}

impl Display for IPv4Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip.dotted_decimal(), self.mask.to_cidr())
    }
}

fn main() {
    // let mut input = String::new();
    // println!("Hello, world!");
    // io::stdin().read_line(&mut input);
    // input = input.trim_end().to_string();
    // println!("{}", input);

    let ip_string = String::from("192.168.0.1/28");

    let regex_cidr = Regex::new(r"^(.*?)[\s/](.*?)$").unwrap();

    match regex_cidr.captures(&ip_string) {
        Some(v) => {

            let ip_part = v.get(1).unwrap().as_str();
            let mask_part = v.get(2).unwrap().as_str();



            let cidr_part = mask_part.parse::<u8>().unwrap();


            let ip = IPv4Address::from_string(ip_part);
            println!("{}", ip.dotted_decimal());

            let netmask = IPv4Mask::from_cidr(cidr_part);
            println!("{}", netmask.dotted_decimal());

            let obj = IPv4Network::new(ip, Some(netmask));
            println!("{}", obj);
            println!("{}", obj.network.dotted_decimal());
            println!("{}", obj.broadcast.dotted_decimal());
        }
        None => println!("Not")
    }
}
