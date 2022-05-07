extern crate core;

use std::fmt::{Display, Formatter};
//use std::io;
use regex::Regex;

///
/// Convert integer representation of 32bit number to dotted decimal.
/// Used for printing values of `IPv4Address` and `IPv4Mask`
///
fn int_to_dotted_decimal(integer: &u32) -> String {
    format!("{}.{}.{}.{}",
            integer >> 24,
            (integer >> 16) & 0xff,
            (integer >> 8) & 0xff,
            integer & 0xff,
    )
}

///
/// Recursively calculate length of subnet mask (CIDR format) from integer value
///
fn int_to_cidr(val: &u32, cidr: u8) -> u8 {
    if val == &0 {
        return cidr;
    }
    int_to_cidr(&(val << 1), cidr + 1)
}

///
/// Convert dotted decimal representation of 32bit number to integer.
/// Used for parsing `IPv4Address` and `IPv4Mask` values from strings
///
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
                |value|
                    match value.parse::<u32>() {
                        Ok(v) if v <= 255 => v,
                        _ => panic!("Invalid dotted decimal format.")
                    }
            );

            let mut int_ip = ip_parts[0] << 24;
            int_ip += ip_parts[1] << 16;
            int_ip += ip_parts[2] << 8;
            int_ip += ip_parts[3];

            return int_ip;
        }
        None => panic!("Invalid dotted decimal format.")
    }
}

///
/// Check if number has contiguous set of 1 bits.
/// Used for validating `IPv4Mask`
///
fn is_contiguous(mut number: u32) -> bool {
    // Count the number of shifts, should be 0 at the end
    let mut counter: u8 = 32;

    // Strip all zeros from the end
    while number > 0 && number % 2 == 0 {
        number >>= 1;
        counter -= 1;
    }

    // Strip all ones from the end
    while number > 0 && number % 2 == 1 {
        number >>= 1;
        counter -= 1;
    }

    // If contiguous, should be zero
    number == 0 && counter == 0
}

struct IPv4Address {
    address: u32,
}

struct IPv4Mask {
    address: u32,
}

impl IPv4Address {
    fn from_string(address_string: &str) -> IPv4Address {
        IPv4Address { address: dotted_decimal_to_int(address_string) }
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    fn get_default_class_cidr(&self) -> u8 {
        if (self.address >> 31) == 0b0 {
            return 8
        } else if (self.address >> 30) == 0b10 {
            return 16
        } else if (self.address >> 29) == 0b110 {
            return 24
        } else {
            panic!("Address not in A, B or C class. No default mask available.")
        }
    }
}

impl IPv4Mask {
    fn from_dotted_decimal(address_string: &str) -> IPv4Mask {
        let mask = IPv4Mask { address: dotted_decimal_to_int(address_string) };
        if mask.is_valid_mask() {
            return mask
        } else {
            panic!("Invalid subnet mask. Must have contiguous bits.")
        }
    }

    fn from_cidr(cidr: u8) -> IPv4Mask {
        IPv4Mask { address: u32::MAX << (32 - cidr) }
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    fn to_cidr(&self) -> u8 {
        int_to_cidr(&self.address, 0)
    }

    fn is_valid_mask(&self) -> bool {
        return is_contiguous(self.address)
    }
}

impl Display for IPv4Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dotted_decimal())
    }
}

impl Display for IPv4Mask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dotted_decimal())
    }
}


struct IPv4Network<'a> {
    ip: &'a IPv4Address,
    mask: &'a IPv4Mask,
    network: IPv4Address,
    broadcast: IPv4Address,
}

impl<'a> IPv4Network<'a> {
    fn new(ip: &'a IPv4Address, mask: &'a IPv4Mask) -> IPv4Network<'a> {

        let network= IPv4Address { address: ip.address & mask.address };
        let broadcast = IPv4Address { address: network.address | (u32::MAX >> mask.to_cidr()) };

        IPv4Network { ip, mask, network, broadcast }
    }

    #[allow(dead_code)]
    fn contains(&self, ip: IPv4Address) -> bool {
        return self.network.address <= ip.address && ip.address <= self.broadcast.address
    }
}

impl <'a> Display for IPv4Network<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip.dotted_decimal(), self.mask.to_cidr())
    }
}

fn main() {

    let ip_string = String::from("10.168.0.1");

    let parts: Vec<&str> = ip_string.split(|c| (c == ' ') || (c == '/')).collect();

    let ip: IPv4Address;
    let mask: IPv4Mask;

    let ip_part = parts[0];
    ip = IPv4Address::from_string(ip_part);

    match parts.len() {
        1 => mask = IPv4Mask::from_cidr(ip.get_default_class_cidr()),
        2 => mask = {
            let mask_part = parts[1];
            match mask_part.parse::<u8>() {
                Ok(v) => IPv4Mask::from_cidr(v),
                Err(_) => IPv4Mask::from_dotted_decimal(mask_part)
            }
        },
        _ => panic!("Invalid input format.")
    }

    let net = IPv4Network::new(&ip, &mask);
    println!("{} / {}", ip, mask);
    println!("{}", net);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cidr_mask() {
        assert_eq!(IPv4Address::from_string("0.0.0.0").get_default_class_cidr(), 8);
        assert_eq!(IPv4Address::from_string("127.255.255.255").get_default_class_cidr(), 8);
        assert_eq!(IPv4Address::from_string("128.0.0.0").get_default_class_cidr(), 16);
        assert_eq!(IPv4Address::from_string("191.255.255.255").get_default_class_cidr(), 16);
        assert_eq!(IPv4Address::from_string("192.0.0.0").get_default_class_cidr(), 24);
        assert_eq!(IPv4Address::from_string("223.255.255.255").get_default_class_cidr(), 24);
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class(){
        IPv4Address::from_string("224.0.0.0").get_default_class_cidr();
        IPv4Address::from_string("255.255.255.255").get_default_class_cidr();
    }
}
