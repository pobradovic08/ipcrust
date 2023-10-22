use std::fmt::{Display, Formatter};
use regex::Regex;

///
/// Convert integer representation of 32bit number to dotted decimal.
/// Used for printing values of `IPv4Address` and `IPv4Mask`
///
pub fn int_to_dotted_decimal(integer: &u32) -> String {
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
pub fn int_to_cidr(val: &u32, cidr: u8) -> u8 {
    if val == &0 {
        return cidr;
    }
    int_to_cidr(&(val << 1), cidr + 1)
}

///
/// Convert dotted decimal representation of 32bit number to integer.
/// Used for parsing `IPv4Address` and `IPv4Mask` values from strings
///
pub fn dotted_decimal_to_int(address_string: &str) -> u32 {
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
pub fn is_contiguous(mut number: u32) -> bool {

    if number == 0 {
        return true;
    }

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

#[derive(Debug, PartialEq)]
pub enum AddressError {
    InvalidAddress,
    InvalidCidr
}

#[derive(Copy, Clone)]
pub struct Address {
    address: u32,
    cidr: u8,
    pub class: AddressClass, //TODO: make private
    _mask: u32,
}

impl Address {
    pub fn from_string(address_string: &str) -> Result<Address, AddressError> {
        return match Address::_parse_string(address_string) {
            Ok((address, cidr)) => {
                let int_value = dotted_decimal_to_int(address);
                Ok(Address::from_int(int_value, Some(cidr)))
            },
            Err(err) => Err(err)
        }
    }

    pub fn from_int(int_value: u32, cidr: Option<u8>) -> Address {
        let class = AddressClass::get(int_value);
        let cidr = cidr.unwrap_or(Address::get_default_class_cidr(class).unwrap_or(32));
        let _mask = Address::cidr_to_mask(cidr);
        Address { address: int_value, class, cidr, _mask }
    }

    fn _parse_string(input: &str) -> Result<(&str, u8), AddressError> {
        let parts: Vec<&str> = input.split(|c| c == '/').collect();
        let address: &str = parts[0];
        let regex_address_v4 = Regex::new(r"^([0-9]{1,3}\.){3}([0-9]{1,3})$").unwrap();

        match parts.len() {
            // IP: <part[0]>
            //TODO: Replace hardcoded CIDR with default class
            1 => return Ok((address, 32u8)),
            // IP: <part[0]>/<part[1]>
            2 => {
                if !regex_address_v4.is_match(address) {
                    return Err(AddressError::InvalidAddress);
                }

                //TODO: return decimal value instead of string
                let address_dec = Address::dotted_decimal_to_int(address)?;

                //Try to parse CIDR as `u8`
                return Ok((address, Address::_parse_mask_format(parts[1])?));
            },
            _ => Err(AddressError::InvalidAddress),
        }
    }

    fn _parse_mask_format(mask: &str) -> Result<u8, AddressError> {
        let regex_address_v4 = Regex::new(r"^([0-9]{1,3}\.){3}([0-9]{1,3})$").unwrap();

        return match mask.parse::<u8>() {
            // String can be parsed to integer (CIDR provided)
            Ok(cidr) => {
                // If the CIDR is above 32, return Err
                if cidr > 32 {
                    return Err(AddressError::InvalidCidr);
                }
                // Else return parsed CIDR
                Ok(cidr)
            },
            // String can't be parsed to integer
            Err(_) => {
                // Check if it's in dotted decimal notation
                // If not, return Err
                if regex_address_v4.is_match(mask) {
                    // Convert dotted decimal notation to decimal
                    let mask_dec = dotted_decimal_to_int(mask);
                    // If the mask is not valid (doesn't have contiguous bits) return Err
                    if !is_contiguous(mask_dec) {
                        return Err(AddressError::InvalidCidr);
                    }
                    // Return the CIDR value for the decimal mask
                    Ok(int_to_cidr(&mask_dec,0))
                }else{
                    Err(AddressError::InvalidCidr)
                }
            },
        }
    }

    /// Convert CIDR mask value to actual mask (32bit number)
    fn cidr_to_mask(cidr: u8) -> u32 {
        if cidr > 32 {
            panic!("Invalid CIDR.");
        }
        match cidr {
            0 => 0,
            _ => u32::MAX << (32 - cidr)
        }
    }

    pub fn dotted_decimal_to_int(address_string: &str) -> Result<u32, AddressError> {
        let regex_dotted_decimal = Regex::new(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$").unwrap();

        match regex_dotted_decimal.captures(&address_string) {
            Some(v) => {
                // Push each octet (capture groups from 1 to 4) to vector
                let mut raw_ip_parts: Vec<u32> = Vec::new();
                for i in 1..=4 {
                    // Get capture group as string or return Err
                    let octet = v.get(i).ok_or(AddressError::InvalidAddress)?.as_str();
                    // Parse octet as CIDR integer or return Err
                    let octet_dec = match octet.parse::<u32>() {
                        Ok(v) if v <= 255 => Ok(v),
                        _ => Err(AddressError::InvalidAddress)
                    }?;
                    // Add octet to vector
                    raw_ip_parts.push(octet_dec);
                }

                // Make an integer from each of the octets by bitwise shifting them
                let mut int_ip = raw_ip_parts[0] << 24;
                int_ip += raw_ip_parts[1] << 16;
                int_ip += raw_ip_parts[2] << 8;
                int_ip += raw_ip_parts[3];

                return Ok(int_ip);
            }
            None => Err(AddressError::InvalidAddress)
        }
    }

    ///
    /// Classes A through C have network masks: /8, /16 and /24 respectively
    ///
    pub fn get_default_class_cidr(class: AddressClass) -> Option<u8> {
        match class {
            AddressClass::A => Some(8),
            AddressClass::B => Some(16),
            AddressClass::C => Some(24),
            _ => None
        }
    }

    pub fn mask_to_wildcard(mask: u32) -> String {
        int_to_dotted_decimal(&!mask)
    }

    pub fn get_usable_hosts(&self) -> u32 {
        match self.cidr {
            32 => 1,
            31 => 2,
            0 => u32::MAX - 1,
            _ => 2u32.pow(32 - self.cidr as u32) - 2
        }
    }

    pub fn get_network_address(&self) -> u32 {
        return match self.cidr {
            32 => self.address,
            _ => self.address & self._mask,
        }
    }

    pub fn get_broadcast_address(&self) -> u32 {
        return match self.cidr {
            32 => self.address,
            _ => self.address | (u32::MAX >> self.cidr),
        }
    }

    pub fn get_first_address(&self) -> u32 {
        match self.is_host() || self.is_p2p() {
            true => self.get_network_address(),
            false => self.get_network_address() + 1,
        }
    }

    pub fn get_last_address(&self) -> u32 {
        match self.is_host() || self.is_p2p() {
            true => self.get_broadcast_address(),
            false => self.get_broadcast_address() - 1,
        }
    }

    #[allow(dead_code)]
    pub fn contains(&self, ip: Address) -> bool {
        return self.get_network_address() <= ip.address && ip.address <= self.get_broadcast_address();
    }

    pub fn is_host(&self) -> bool {
        return self._mask == u32::MAX;
    }

    pub fn is_p2p(&self) -> bool {
        return self._mask == u32::MAX - 1;
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", int_to_dotted_decimal(&self.address))
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AddressClass { A, B, C, D, E, ZERO, BROADCAST }

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

    fn get_additional_info(address: Address) -> Vec<String> {
        let n = |network: &str| Address::from_string(network).unwrap();
        let mut info_array: Vec<String> = vec!();

        let address_info_map: [(Address, &str); 16] = [
            (n("0.0.0.0/8"), "Source hosts on 'this' network - RFC1122"),
            (n("10.0.0.0/8"), "Class A private address - RFC1918"),
            (n("100.64.0.0/10"), "Shared address space - RFC6598"),
            (n("127.0.0.0/8"), "Loopback addresses - RFC1122"),
            (n("169.254.0.0/16"), "Link local address block - RFC3927"),
            (n("172.16.0.0/12"), "Class B private address - RFC1918"),
            (n("192.0.0.0/24"), "Reserved for IETF protocol assignments - RFC5736"),
            (n("192.0.2.0/24"), "For use in documentation and example code - RFC5737"),
            (n("192.88.99.0/24"), "6to4 Relay Anycast - RFC3068"),
            (n("192.168.0.0/16"), "Class C private address - RFC1918"),
            (n("198.18.0.0/15"), "Device Benchmark Testing addressing - RFC2544"),
            (n("198.51.100.0/25"), "For use in documentation and example code - RFC5737"),
            (n("203.0.113.0/24"), "For use in documentation and example code - RFC5737"),
            (n("224.0.0.0/4"), "Multicast - RFC3171"),
            (n("240.0.0.0/24"), "Reserved for Future Use - RFC1112"),
            (n("255.255.255.255/32"), "Limited Broadcast - RFC919, RFC922")
        ];

        for (network, note) in address_info_map {
            if network.contains(address) {
                info_array.push(String::from(note))
            }
        }

        info_array
    }

    fn get_class_no_bits(&self) -> u8 {
        match self {
            AddressClass::A => 1,
            AddressClass::B => 2,
            AddressClass::C => 3,
            AddressClass::D | AddressClass::E => 4,
            AddressClass::ZERO => 0,
            AddressClass::BROADCAST => 0
        }
    }
}

impl Display for AddressClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressClass::A => write!(f, "Class A"),
            AddressClass::B => write!(f, "Class B"),
            AddressClass::C => write!(f, "Class C"),
            AddressClass::D => write!(f, "Class D"),
            AddressClass::E => write!(f, "Class E"),
            AddressClass::ZERO => write!(f, "Zero address"),
            AddressClass::BROADCAST => write!(f, "Broadcast address")
        }
    }
}

pub fn print_binary_colored(ip: Address, position: u8) -> String {
    let tmp = format!("{:032b}", ip.address);

    let mut class_part = String::new();
    let mut network_part = String::new();
    let mut host_part = String::new();

    let mut ptr = &mut class_part;

    for (i, char) in tmp.chars().enumerate() {
        if i == ip.class.get_class_no_bits() as usize {
            ptr = &mut network_part;
        }
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
            }
            _ => {
                ptr.push('░');
                ptr.push('░');
            }
        }
    }

    //let (network_part, host_part) = replaced.split_at(position as usize);

    format!("\x1b[38;5;198m{}\x1b[38;5;38m{}\x1b[38;5;214m{}\x1b[0m", class_part, network_part, host_part)
}

pub fn print_results(net: &Address) {
    let tw = 71;

    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!("\x1b[1;38;5;10m █ Address:    {}/{}\x1b[0m", net, net.cidr),
             format!("\x1b[0;38;5;38m ░ Class:      {:18}\x1b[0m", net.class),
             (tw + 29) / 2
    );
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Mask:       {:18}", int_to_dotted_decimal(&net._mask)),
             format!(" ░ Wildcard:   {:18}", Address::mask_to_wildcard(net._mask)),
             (tw - 2) / 2
    );
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Network:    {:18}", int_to_dotted_decimal(&net.get_network_address())),
             format!(" ░ First IPv4: {:18}", int_to_dotted_decimal(&net.get_first_address())),
             (tw - 2) / 2
    );
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Broadcast:  {:18}", int_to_dotted_decimal(&net.get_broadcast_address())),
             format!(" ░ Last IPv4:  {:18}", int_to_dotted_decimal(&net.get_last_address())),
             (tw - 2) / 2
    );
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:<1$}│", format!("\x1b[1m ░ Max hosts:  {}\x1b[0m", net.get_usable_hosts()), tw + 6);
    println!("│{:^1$}│", "", tw - 2);
    if net.is_host() {
        println!("│{:<1$}│", "\x1b[38;5;214m ░ Note: Network represents a host (/32 route).\x1b[0m", tw + 13);
    }
    if net.is_p2p() {
        println!("│{:<1$}│", "\x1b[38;5;214m ░ Note: Network is an P2P network (/31).\x1b[0m", tw + 13);
    }

    for note in AddressClass::get_additional_info(*net) {
        println!("│{:<1$}│", format!("\x1b[38;5;198m ░ Note: {}.\x1b[0m", note), tw + 13);
    }

    println!("├{:─^1$}┤", "", tw - 2);
    println!("│{:<1$}│", "\x1b[1m ░ Binary address representation:\x1b[0m", tw + 6);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:<1$}│", "\x1b[38;5;198m █░ Class part \x1b[38;5;38m █░ Network part \x1b[38;5;214m █░ Hosts part \x1b[0m", tw + 34);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:<1$}│", " 01            08 09            16 17            24 25            32", tw - 2);
    println!("│{:<1$}│", "\x1b[38;5;244m ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄   ▄▄  ▄▄  ▄▄  ▄▄  \x1b[0m", tw + 13);
    println!("│{:<1$}│", format!("{:>80}",
                                 print_binary_colored(*net, net.cidr)),
             tw + 34);
    //println!("│{:<1$}│", " ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤ ├┘└┘└┘└┘└┘└┘└┘└┤", tw - 2);
    println!("│{:<1$}│", " └── OCTET  1 ──┘ └── OCTET  2 ──┘ └── OCTET  3 ──┘ └── OCTET  4 ──┘", tw - 2);
    println!("│{:^1$}│", "", tw - 2);
    println!("└{:─^1$}┘", "", tw - 2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print() {
        let network = Address::from_string("192.0.2.2/30").unwrap();
        print_results(&network);
    }

    #[test]
    fn test_int_to_dotted_notation() {
        assert_eq!(int_to_dotted_decimal(&0u32), "0.0.0.0");
        assert_eq!(int_to_dotted_decimal(&16909060u32), "1.2.3.4");
        assert_eq!(int_to_dotted_decimal(&524548u32), "0.8.1.4");
        assert_eq!(int_to_dotted_decimal(&4294967295u32), "255.255.255.255");
        assert_eq!(int_to_dotted_decimal(&4278190080u32), "255.0.0.0");
    }

    #[test]
    fn test_int_to_cidr() {
        assert_eq!(int_to_cidr(&0u32, 0), 0);
        assert_eq!(int_to_cidr(&4278190080u32, 0), 8);
        assert_eq!(int_to_cidr(&4294901760u32, 0), 16);
        assert_eq!(int_to_cidr(&4294967040u32, 0), 24);
        assert_eq!(int_to_cidr(&4294967294u32, 0), 31);
        assert_eq!(int_to_cidr(&4294967295u32, 0), 32);
    }

    #[test]
    fn test_int_to_cidr_invalid() {
        //TODO: Add checks for invalid CIDR
    }

    #[test]
    fn test_dotted_decimal_to_int() {
        assert_eq!(dotted_decimal_to_int("0.0.0.0"), 0);
        assert_eq!(dotted_decimal_to_int("1.2.3.4"), 16909060);
        assert_eq!(dotted_decimal_to_int("0.8.1.4"), 524548);
        assert_eq!(dotted_decimal_to_int("255.255.255.255"), 4294967295);
        assert_eq!(dotted_decimal_to_int("255.0.0.0"), 4278190080);
    }

    #[test]
    #[should_panic]
    fn test_dotted_decimal_to_int_invalid() {
        dotted_decimal_to_int("0..0.0");
        dotted_decimal_to_int("0.256.0.0");
        dotted_decimal_to_int("0.0.0");
        dotted_decimal_to_int("0.a.0.0");
        dotted_decimal_to_int("0.-1.0.0");
    }

    #[test]
    fn test_is_contiguous() {
        assert_eq!(is_contiguous(0), true);
        assert_eq!(is_contiguous(1), false);

        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask = 0xffffffff << shift;
            assert_eq!(is_contiguous(mask), true);


            if shift == 32 || shift <= 1 {
                continue;
            }
            assert_eq!(is_contiguous(mask-1), false);
            assert_eq!(is_contiguous(mask+1), false);
        }
    }

    #[test]
    fn test_ip_class() {
        assert_eq!(AddressClass::get(Address::from_string("0.0.0.0").unwrap().address), AddressClass::ZERO);
        assert_eq!(AddressClass::get(Address::from_string("0.0.0.1").unwrap().address), AddressClass::A);
        assert_eq!(AddressClass::get(Address::from_string("127.255.255.255").unwrap().address), AddressClass::A);
        assert_eq!(AddressClass::get(Address::from_string("128.0.0.0").unwrap().address), AddressClass::B);
        assert_eq!(AddressClass::get(Address::from_string("191.255.255.255").unwrap().address), AddressClass::B);
        assert_eq!(AddressClass::get(Address::from_string("192.0.0.0").unwrap().address), AddressClass::C);
        assert_eq!(AddressClass::get(Address::from_string("223.255.255.255").unwrap().address), AddressClass::C);
        assert_eq!(AddressClass::get(Address::from_string("224.0.0.0").unwrap().address), AddressClass::D);
        assert_eq!(AddressClass::get(Address::from_string("239.255.255.255").unwrap().address), AddressClass::D);
        assert_eq!(AddressClass::get(Address::from_string("240.0.0.0").unwrap().address), AddressClass::E);
        assert_eq!(AddressClass::get(Address::from_string("255.255.255.254").unwrap().address), AddressClass::E);
        assert_eq!(AddressClass::get(Address::from_string("255.255.255.255").unwrap().address), AddressClass::BROADCAST);
    }

    #[test]
    fn test_mask_parsing() {
        assert_eq!(Address::_parse_mask_format("255.255.255.0").unwrap(), 24);
        assert_eq!(Address::_parse_mask_format("255.255.255.255").unwrap(), 32);
        assert_eq!(Address::_parse_mask_format("24").unwrap(), 24);
    }

    #[test]
    fn test_mask_parsing_invalid() {
        assert!(matches!(Address::_parse_mask_format(""), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_mask_format("asdf"), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_mask_format("33"), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_mask_format("-1"), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_mask_format("255.255.0.255"), Err(AddressError::InvalidCidr)));
    }

    #[test]
    fn test_string_parsing() {
        assert_eq!(Address::_parse_string("10.0.0.0/255.255.255.0").unwrap(), ("10.0.0.0", 24));
        assert_eq!(Address::_parse_string("10.0.0.0/24").unwrap(), ("10.0.0.0", 24));
        assert_eq!(Address::_parse_string("10.0.0.0/32").unwrap(), ("10.0.0.0", 32));
        assert_eq!(Address::_parse_string("10.0.0.0").unwrap(), ("10.0.0.0", 32));
    }

    #[test]
    fn test_string_parsing_invalid() {
        assert!(matches!(Address::_parse_string("10.0.0.0/255.255.0.255"), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_string("10.0.0.0/244"), Err(AddressError::InvalidCidr)));
        assert!(matches!(Address::_parse_string("10.256.0.0/24"), Err(AddressError::InvalidAddress)));
        assert!(matches!(Address::_parse_string("10.10.0./24"), Err(AddressError::InvalidAddress)));
        assert!(matches!(Address::_parse_string("10.10.0/24"), Err(AddressError::InvalidAddress)));
        assert!(matches!(Address::_parse_string("asd/24"), Err(AddressError::InvalidAddress)));
    }

    #[test]
    fn test_address_from_dec() {
        assert_eq!(Address::from_int(0u32, None).address, 0u32);
        assert_eq!(Address::from_int(16909060u32, None).address, 16909060u32);
        assert_eq!(Address::from_int(524548u32, None).address, 524548u32);
        assert_eq!(Address::from_int(4294967295u32, None).address, 4294967295u32);
        assert_eq!(Address::from_int(4278190080u32, None).address, 4278190080u32);
    }

    #[test]
    fn test_address_from_string() {
        assert_eq!(Address::from_string("0.0.0.0").unwrap().address, 0u32);
        assert_eq!(Address::from_string("1.2.3.4").unwrap().address, 16909060u32);
        assert_eq!(Address::from_string("0.8.1.4").unwrap().address, 524548u32);
        assert_eq!(Address::from_string("255.255.255.255").unwrap().address, 4294967295u32);
        assert_eq!(Address::from_string("255.0.0.0").unwrap().address, 4278190080u32);
    }

    #[test]
    fn test_address_dotted_decimal() {
        for ip in ["0.0.0.0", "1.2.3.4", "0.8.1.4", "255.255.255.255", "255.0.0.0"] {
            let address = Address::from_string(ip).unwrap();
            assert_eq!(int_to_dotted_decimal(&address.address), ip);
        }
    }

    #[test]
    fn test_mask_from_cidr() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask = 0xffffffff << shift;
            assert_eq!(Address::cidr_to_mask(32-shift), mask);
        }
    }

    #[test]
    fn test_mask_from_string_and_cidr() {
        assert_eq!(dotted_decimal_to_int("0.0.0.0"), Address::cidr_to_mask(0));
        assert_eq!(dotted_decimal_to_int("255.255.255.0"), Address::cidr_to_mask(24));
        assert_eq!(dotted_decimal_to_int("255.255.0.0"), Address::cidr_to_mask(16));
        assert_eq!(dotted_decimal_to_int("255.255.255.255"), Address::cidr_to_mask(32));
        assert_eq!(dotted_decimal_to_int("255.255.255.254"), Address::cidr_to_mask(31));
    }

    #[test]
    fn test_mask_wildcard() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask: u32 = 0xffffffff << shift;
            assert_eq!(Address::mask_to_wildcard(Address::cidr_to_mask(32 - shift)), int_to_dotted_decimal(&!mask));
        }
    }

    #[test]
    #[should_panic]
    fn test_mask_invalid_cidr() {
        Address::cidr_to_mask(33);
    }

    #[test]
    fn test_default_cidr_mask() {
        assert_eq!(Address::get_default_class_cidr(Address::from_string("0.0.0.1").unwrap().class).unwrap(), 8);
        assert_eq!(Address::get_default_class_cidr(Address::from_string("127.255.255.255").unwrap().class).unwrap(), 8);
        assert_eq!(Address::get_default_class_cidr(Address::from_string("128.0.0.0").unwrap().class).unwrap(), 16);
        assert_eq!(Address::get_default_class_cidr(Address::from_string("191.255.255.255").unwrap().class).unwrap(), 16);
        assert_eq!(Address::get_default_class_cidr(Address::from_string("192.0.0.0").unwrap().class).unwrap(), 24);
        assert_eq!(Address::get_default_class_cidr(Address::from_string("223.255.255.255").unwrap().class).unwrap(), 24);
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_zeros() {
        Address::get_default_class_cidr(Address::from_string("0.0.0.0").unwrap().class).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_start() {
        Address::get_default_class_cidr(Address::from_string("224.0.0.0").unwrap().class).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_end() {
        Address::get_default_class_cidr(Address::from_string("239.255.255.255").unwrap().class).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_start() {
        Address::get_default_class_cidr(Address::from_string("240.0.0.0").unwrap().class).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_end() {
        Address::get_default_class_cidr(Address::from_string("255.255.255.254").unwrap().class).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_broadcast() {
        Address::get_default_class_cidr(Address::from_string("255.255.255.255").unwrap().class).unwrap();
    }

    #[test]
    fn test_network() {
        let address = Address::from_string("192.0.2.2/24").unwrap();

        assert_eq!(address.address, dotted_decimal_to_int("192.0.2.2"));
        assert_eq!(address.cidr, 24);
        assert_eq!("192.0.2.0", int_to_dotted_decimal(&address.get_network_address()));
        assert_eq!("192.0.2.255", int_to_dotted_decimal(&address.get_broadcast_address()));

        let address = Address::from_string("192.0.2.2/32").unwrap();

        assert_eq!(address.address, dotted_decimal_to_int("192.0.2.2"));
        assert_eq!(address.cidr, 32);
        assert_eq!("192.0.2.2", int_to_dotted_decimal(&address.get_network_address()));
        assert_eq!("192.0.2.2", int_to_dotted_decimal(&address.get_broadcast_address()));
    }

    #[test]
    fn test_network_first_address() {
        let address = Address::from_string("192.0.2.2/24").unwrap();
        assert_eq!("192.0.2.1", int_to_dotted_decimal(&address.get_first_address()));

        let address = Address::from_string("192.0.2.2/31").unwrap();
        assert_eq!("192.0.2.2", int_to_dotted_decimal(&address.get_first_address()));

        let address = Address::from_string("192.0.2.2/32").unwrap();
        assert_eq!("192.0.2.2", int_to_dotted_decimal(&address.get_first_address()));
    }

    #[test]
    fn test_network_last_address() {
        let address = Address::from_string("192.0.2.2/24").unwrap();
        assert_eq!("192.0.2.254", int_to_dotted_decimal(&address.get_last_address()));

        let address = Address::from_string("192.0.2.2/31").unwrap();
        assert_eq!("192.0.2.3", int_to_dotted_decimal(&address.get_last_address()));

        let address = Address::from_string("192.0.2.2/32").unwrap();
        assert_eq!("192.0.2.2", int_to_dotted_decimal(&address.get_last_address()));
    }

    #[test]
    fn test_network_usable_hosts() {
        let network = Address::from_string("192.0.2.2/24").unwrap();
        assert_eq!(network.get_usable_hosts(), 254);
        let network = Address::from_string("192.0.2.2/30").unwrap();
        assert_eq!(network.get_usable_hosts(), 2);
        let network = Address::from_string("192.0.2.2/31").unwrap();
        assert_eq!(network.get_usable_hosts(), 2);
        let network = Address::from_string("192.0.2.2/32").unwrap();
        assert_eq!(network.get_usable_hosts(), 1);
        let network = Address::from_string("1.1.1.1/0").unwrap();
        assert_eq!(network.get_usable_hosts(), 4294967294);
    }

    #[test]
    fn test_network_is_host() {
        let network = Address::from_string("192.0.2.2/0").unwrap();
        assert_eq!(network.is_host(), false);
        let network = Address::from_string("192.0.2.2/30").unwrap();
        assert_eq!(network.is_host(), false);
        let network = Address::from_string("192.0.2.2/31").unwrap();
        assert_eq!(network.is_host(), false);
        let network = Address::from_string("192.0.2.2/32").unwrap();
        assert_eq!(network.is_host(), true);
    }

    #[test]
    fn test_network_is_p2p() {
        let network = Address::from_string("192.0.2.2/0").unwrap();
        assert_eq!(network.is_p2p(), false);
        let network = Address::from_string("192.0.2.2/30").unwrap();
        assert_eq!(network.is_p2p(), false);
        let network = Address::from_string("192.0.2.2/31").unwrap();
        assert_eq!(network.is_p2p(), true);
        let network = Address::from_string("192.0.2.2/32").unwrap();
        assert_eq!(network.is_p2p(), false);
    }
}
