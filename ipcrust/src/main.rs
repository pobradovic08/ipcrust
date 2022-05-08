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
    class: AddressClass,
}

struct IPv4Mask {
    address: u32,
}

impl IPv4Address {
    fn from_string(address_string: &str) -> IPv4Address {
        let int_value = dotted_decimal_to_int(address_string);
        let class = AddressClass::get(int_value);
        IPv4Address { address: int_value, class }
    }

    fn from_int(int_value: u32) -> IPv4Address {
        let class = AddressClass::get(int_value);
        IPv4Address { address: int_value, class }
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    ///
    /// Classes A through C have network masks: /8, /16 and /24 respectively
    ///
    fn get_default_class_cidr(&self) -> u8 {
        match self.class {
            AddressClass::A => 8,
            AddressClass::B => 16,
            AddressClass::C => 24,
            _ => panic!("Address not in A, B or C class. No default mask available.")
        }
    }
}

impl IPv4Mask {
    fn from_dotted_decimal(address_string: &str) -> IPv4Mask {
        let mask = IPv4Mask { address: dotted_decimal_to_int(address_string) };
        if mask.is_valid_mask() {
            return mask;
        } else {
            panic!("Invalid subnet mask. Must have contiguous bits.")
        }
    }

    fn from_cidr(cidr: u8) -> IPv4Mask {
        match cidr {
            0 => IPv4Mask { address: 0 },
            _ => IPv4Mask { address: u32::MAX << (32 - cidr) }
        }
    }

    fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    fn to_cidr(&self) -> u8 {
        int_to_cidr(&self.address, 0)
    }

    fn is_valid_mask(&self) -> bool {
        return is_contiguous(self.address);
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

#[derive(Debug, PartialEq)]
enum AddressClass { A, B, C, D, E, ZERO, BROADCAST }

impl AddressClass {
    ///
    /// | Class   | 1st octet value |
    /// |---------|-----------------|
    /// | A       | 1 - 127         |
    /// | B       | 128 - 191       |
    /// | C       | 192 - 223       |
    /// | D       | 224 - 239       |
    /// | E       | 240 - 255       |
    ///
    /// Matching the most significant bits for A-C classes:
    ///
    /// ```
    /// Class A - 0xxxxxxx
    /// Class B - 10xxxxxx
    /// Class C - 110xxxxx
    /// Class D - 1110xxxx
    /// Class E - 1111xxxx
    /// ```
    ///
    fn get(address: u32) -> AddressClass {
        return if address == 0 {
            AddressClass::ZERO
        } else if address == u32::MAX {
            AddressClass::BROADCAST
        } else if (address >> 31) == 0b0 {
            AddressClass::A
        } else if (address >> 30) == 0b10 {
            AddressClass::B
        } else if (address >> 29) == 0b110 {
            AddressClass::C
        } else if (address >> 28) == 0b1110 {
            AddressClass::D
        } else {
            AddressClass::E
        };
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
        let network: IPv4Address;
        let broadcast: IPv4Address;

        match mask.to_cidr() {
            32 => {
                network = IPv4Address::from_int(ip.address);
                broadcast = IPv4Address::from_int(ip.address);
            }
            _ => {
                network = IPv4Address::from_int(ip.address & mask.address);
                broadcast = IPv4Address::from_int(network.address | (u32::MAX >> mask.to_cidr()));
            }
        }

        IPv4Network { ip, mask, network, broadcast }
    }

    fn get_first_address(&self) -> IPv4Address {
        if self.is_host() || self.is_p2p() {
            return IPv4Address::from_int(self.network.address);
        }
        IPv4Address::from_int(self.network.address + 1)
    }

    fn get_last_address(&self) -> IPv4Address {
        if self.is_host() || self.is_p2p() {
            return IPv4Address::from_int(self.broadcast.address);
        }
        IPv4Address::from_int(self.broadcast.address - 1)
    }

    #[allow(dead_code)]
    fn contains(&self, ip: IPv4Address) -> bool {
        return self.network.address <= ip.address && ip.address <= self.broadcast.address;
    }

    fn is_host(&self) -> bool {
        return self.mask.address == u32::MAX;
    }

    fn is_p2p(&self) -> bool {
        return self.mask.address == u32::MAX - 1;
    }
}

impl<'a> Display for IPv4Network<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip.dotted_decimal(), self.mask.to_cidr())
    }
}

fn print_binary_colored(address: u32, position: u8) -> String {
    let tmp = format!("{:b}", address);
    let mut network_part = String::new();
    let mut host_part = String::new();

    let mut ptr = &mut network_part;

    for (i, char) in tmp.chars().enumerate() {
        if i == position as usize {
            ptr = &mut host_part;
        }
        if i % 8 == 0 {
            ptr.push(' ');
        }
        match char {
            '1' => {
                ptr.push('█');
                ptr.push('█');
            },
            _ => {
                ptr.push('░');
                ptr.push('░');
            }
        }
    }

    //let (network_part, host_part) = replaced.split_at(position as usize);

    format!("\x1b[94m{}\x1b[38;5;214m{}\x1b[0m", network_part, host_part)
}

fn print_results(net: &IPv4Network) {
    let tw = 71;

    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!("\x1b[1;92m ▒ Address:    {}/{}\x1b[0m", net.ip, net.mask.to_cidr()),
             format!("\x1b[1;96m ░ Class:      {:18}\x1b[0m", "Class A"),
             (tw + 20) / 2
    );
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Mask:       {:18}", net.mask),
             format!(" ░ Wildcard:   {:18}", net.mask),
             (tw - 2) / 2
    );
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Network:    {:18}", net.network),
             format!(" ░ First IPv4: {:18}", net.get_first_address()),
             (tw - 2) / 2
    );
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Broadcast:  {:18}", net.broadcast),
             format!(" ░ Last IPv4:  {:18}", net.get_last_address()),
             (tw - 2) / 2
    );
    println!("│{:^1$}│", "", tw - 2);
    if net.is_host() {
        println!("│{:<1$}│", "\x1b[93m ░ Note: Network represents a host (/32 route).\x1b[0m", tw + 7);
    }
    if net.is_p2p() {
        println!("│{:<1$}│", "\x1b[93m ░ Note: Network is an P2P network (/31).\x1b[0m", tw + 7);
    }
    println!("├{:─^1$}┤", "", tw - 2);
    println!("│{:<1$}│", "\x1b[1m ▒ Binary address representation:\x1b[0m", tw + 6);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:<1$}│", "\x1b[94m █▒ Network part \x1b[38;5;214m █▒ Hosts part \x1b[0m", tw + 18);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:<1$}│", " 01            08 09            16 17            24 25            32", tw - 2);
    println!("│{:<1$}│", "\x1b[38;5;244m ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄  \x1b[0m", tw + 13);
    println!("│{:<1$}│", format!("{:>80}",
                                 print_binary_colored(net.ip.address, net.mask.to_cidr())),
             tw + 18);
    //println!("│{:<1$}│", " ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤", tw - 2);
    println!("│{:<1$}│", " └── OCTET  1 ──┘ └── OCTET  2 ──┘ └── OCTET  3 ──┘ └── OCTET  4 ──┘", tw - 2);
    println!("│{:^1$}│", "", tw - 2);
    println!("└{:─^1$}┘", "", tw - 2);
}

fn main() {
    let ip_string = String::from("192.168.255.123/24");

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
    print_results(&net);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_class() {
        assert_eq!(AddressClass::get(IPv4Address::from_string("0.0.0.0").address), AddressClass::ZERO);
        assert_eq!(AddressClass::get(IPv4Address::from_string("0.0.0.1").address), AddressClass::A);
        assert_eq!(AddressClass::get(IPv4Address::from_string("127.255.255.255").address), AddressClass::A);
        assert_eq!(AddressClass::get(IPv4Address::from_string("128.0.0.0").address), AddressClass::B);
        assert_eq!(AddressClass::get(IPv4Address::from_string("191.255.255.255").address), AddressClass::B);
        assert_eq!(AddressClass::get(IPv4Address::from_string("192.0.0.0").address), AddressClass::C);
        assert_eq!(AddressClass::get(IPv4Address::from_string("223.255.255.255").address), AddressClass::C);
        assert_eq!(AddressClass::get(IPv4Address::from_string("224.0.0.0").address), AddressClass::D);
        assert_eq!(AddressClass::get(IPv4Address::from_string("239.255.255.255").address), AddressClass::D);
        assert_eq!(AddressClass::get(IPv4Address::from_string("240.0.0.0").address), AddressClass::E);
        assert_eq!(AddressClass::get(IPv4Address::from_string("255.255.255.254").address), AddressClass::E);
        assert_eq!(AddressClass::get(IPv4Address::from_string("255.255.255.255").address), AddressClass::BROADCAST);
    }

    #[test]
    fn test_default_cidr_mask() {
        assert_eq!(IPv4Address::from_string("0.0.0.1").get_default_class_cidr(), 8);
        assert_eq!(IPv4Address::from_string("127.255.255.255").get_default_class_cidr(), 8);
        assert_eq!(IPv4Address::from_string("128.0.0.0").get_default_class_cidr(), 16);
        assert_eq!(IPv4Address::from_string("191.255.255.255").get_default_class_cidr(), 16);
        assert_eq!(IPv4Address::from_string("192.0.0.0").get_default_class_cidr(), 24);
        assert_eq!(IPv4Address::from_string("223.255.255.255").get_default_class_cidr(), 24);
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_zeros() {
        IPv4Address::from_string("0.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_start() {
        IPv4Address::from_string("224.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_end() {
        IPv4Address::from_string("239.255.255.255").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_start() {
        IPv4Address::from_string("240.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_end() {
        IPv4Address::from_string("255.255.255.254").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_broadcast() {
        IPv4Address::from_string("255.255.255.255").get_default_class_cidr();
    }
}
