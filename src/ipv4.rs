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

#[derive(Copy, Clone)]
pub struct Address {
    address: u32,
    class: AddressClass,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Mask {
    address: u32,
}

impl Address {
    pub fn from_string(address_string: &str) -> Address {
        let int_value = dotted_decimal_to_int(address_string);
        let class = AddressClass::get(int_value);
        Address { address: int_value, class }
    }

    pub fn from_int(int_value: u32) -> Address {
        let class = AddressClass::get(int_value);
        Address { address: int_value, class }
    }

    pub fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    ///
    /// Classes A through C have network masks: /8, /16 and /24 respectively
    ///
    pub fn get_default_class_cidr(&self) -> u8 {
        match self.class {
            AddressClass::A => 8,
            AddressClass::B => 16,
            AddressClass::C => 24,
            _ => panic!("Address not in A, B or C class. No default mask available.")
        }
    }
}

impl Mask {
    pub fn from_dotted_decimal(address_string: &str) -> Mask {
        let mask = Mask { address: dotted_decimal_to_int(address_string) };
        if mask.is_valid_mask() {
            return mask;
        } else {
            panic!("Invalid subnet mask. Must have contiguous bits.")
        }
    }

    pub fn from_cidr(cidr: u8) -> Mask {
        if cidr > 32 {
            panic!("Invalid CIDR");
        }
        match cidr {
            0 => Mask { address: 0 },
            _ => Mask { address: u32::MAX << (32 - cidr) }
        }
    }

    pub fn dotted_decimal(&self) -> String {
        int_to_dotted_decimal(&self.address)
    }

    pub fn to_cidr(&self) -> u8 {
        int_to_cidr(&self.address, 0)
    }

    pub fn to_wildcard(&self) -> String {
        int_to_dotted_decimal(&!self.address)
    }

    pub fn is_valid_mask(&self) -> bool {
        is_contiguous(self.address)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dotted_decimal())
    }
}

impl Display for Mask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dotted_decimal())
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
        let n = |network: &str, cidr: u8| Network::from_string_cidr(network, cidr);
        let mut info_array: Vec<String> = vec!();

        let address_info_map: [(Network, &str); 16] = [
            (n("0.0.0.0", 8), "Source hosts on 'this' network - RFC1122"),
            (n("10.0.0.0", 8), "Class A private address - RFC1918"),
            (n("100.64.0.0", 10), "Shared address space - RFC6598"),
            (n("127.0.0.0", 8), "Loopback addresses - RFC1122"),
            (n("169.254.0.0", 16), "Link local address block - RFC3927"),
            (n("172.16.0.0", 12), "Class B private address - RFC1918"),
            (n("192.0.0.0", 24), "Reserved for IETF protocol assignments - RFC5736"),
            (n("192.0.2.0", 24), "For use in documentation and example code - RFC5737"),
            (n("192.88.99.0", 24), "6to4 Relay Anycast - RFC3068"),
            (n("192.168.0.0", 16), "Class C private address - RFC1918"),
            (n("198.18.0.0", 15), "Device Benchmark Testing addressing - RFC2544"),
            (n("198.51.100.0", 24), "For use in documentation and example code - RFC5737"),
            (n("203.0.113.0", 24), "For use in documentation and example code - RFC5737"),
            (n("224.0.0.0", 4), "Multicast - RFC3171"),
            (n("240.0.0.0", 24), "Reserved for Future Use - RFC1112"),
            (n("255.255.255.255", 32), "Limited Broadcast - RFC919, RFC922")
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

pub struct Network {
    ip: Address,
    mask: Mask,
    network: Address,
    broadcast: Address,
}

impl Network {
    pub fn new(ip: Address, mask: Mask) -> Network {
        let network: Address;
        let broadcast: Address;

        match mask.to_cidr() {
            32 => {
                network = Address::from_int(ip.address);
                broadcast = Address::from_int(ip.address);
            }
            _ => {
                network = Address::from_int(ip.address & mask.address);
                broadcast = Address::from_int(network.address | (u32::MAX >> mask.to_cidr()));
            }
        }

        Network { ip, mask, network, broadcast }
    }

    pub fn from_string_cidr(network: &str, cidr: u8) -> Network {
        let ip = Address::from_string(network);
        let mask = Mask::from_cidr(cidr);

        Network::new(ip, mask)
    }

    pub fn get_first_address(&self) -> Address {
        if self.is_host() || self.is_p2p() {
            return Address::from_int(self.network.address);
        }
        Address::from_int(self.network.address + 1)
    }

    pub fn get_last_address(&self) -> Address {
        if self.is_host() || self.is_p2p() {
            return Address::from_int(self.broadcast.address);
        }
        Address::from_int(self.broadcast.address - 1)
    }

    pub fn get_usable_hosts(&self) -> u32 {
        match self.mask.to_cidr() {
            32 => 1,
            31 => 2,
            _ => 2u32.pow(32 - self.mask.to_cidr() as u32) - 2
        }
    }

    #[allow(dead_code)]
    pub fn contains(&self, ip: Address) -> bool {
        return self.network.address <= ip.address && ip.address <= self.broadcast.address;
    }

    pub fn is_host(&self) -> bool {
        return self.mask.address == u32::MAX;
    }

    pub fn is_p2p(&self) -> bool {
        return self.mask.address == u32::MAX - 1;
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip.dotted_decimal(), self.mask.to_cidr())
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

pub fn print_results(net: &Network) {
    let tw = 71;

    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!("\x1b[1;38;5;10m █ Address:    {}/{}\x1b[0m", net.ip, net.mask.to_cidr()),
             format!("\x1b[0;38;5;38m ░ Class:      {:18}\x1b[0m", net.ip.class),
             (tw + 29) / 2
    );
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<2$} {1:<2$}│",
             format!(" ░ Mask:       {:18}", net.mask),
             format!(" ░ Wildcard:   {:18}", net.mask.to_wildcard()),
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
    println!("│{:<1$}│", format!("\x1b[1m ░ Max hosts:  {}\x1b[0m", net.get_usable_hosts()), tw + 6);
    println!("│{:^1$}│", "", tw - 2);
    if net.is_host() {
        println!("│{:<1$}│", "\x1b[38;5;214m ░ Note: Network represents a host (/32 route).\x1b[0m", tw + 13);
    }
    if net.is_p2p() {
        println!("│{:<1$}│", "\x1b[38;5;214m ░ Note: Network is an P2P network (/31).\x1b[0m", tw + 13);
    }

    for note in AddressClass::get_additional_info(net.ip) {
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
                                 print_binary_colored(net.ip, net.mask.to_cidr())),
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
        let network = Network::from_string_cidr("192.0.2.2", 30);
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
        assert_eq!(AddressClass::get(Address::from_string("0.0.0.0").address), AddressClass::ZERO);
        assert_eq!(AddressClass::get(Address::from_string("0.0.0.1").address), AddressClass::A);
        assert_eq!(AddressClass::get(Address::from_string("127.255.255.255").address), AddressClass::A);
        assert_eq!(AddressClass::get(Address::from_string("128.0.0.0").address), AddressClass::B);
        assert_eq!(AddressClass::get(Address::from_string("191.255.255.255").address), AddressClass::B);
        assert_eq!(AddressClass::get(Address::from_string("192.0.0.0").address), AddressClass::C);
        assert_eq!(AddressClass::get(Address::from_string("223.255.255.255").address), AddressClass::C);
        assert_eq!(AddressClass::get(Address::from_string("224.0.0.0").address), AddressClass::D);
        assert_eq!(AddressClass::get(Address::from_string("239.255.255.255").address), AddressClass::D);
        assert_eq!(AddressClass::get(Address::from_string("240.0.0.0").address), AddressClass::E);
        assert_eq!(AddressClass::get(Address::from_string("255.255.255.254").address), AddressClass::E);
        assert_eq!(AddressClass::get(Address::from_string("255.255.255.255").address), AddressClass::BROADCAST);
    }


    #[test]
    fn test_address_from_dec() {
        assert_eq!(Address::from_int(0u32).address, 0u32);
        assert_eq!(Address::from_int(16909060u32).address, 16909060u32);
        assert_eq!(Address::from_int(524548u32).address, 524548u32);
        assert_eq!(Address::from_int(4294967295u32).address, 4294967295u32);
        assert_eq!(Address::from_int(4278190080u32).address, 4278190080u32);
    }

    #[test]
    fn test_address_from_string() {
        assert_eq!(Address::from_string("0.0.0.0").address, 0u32);
        assert_eq!(Address::from_string("1.2.3.4").address, 16909060u32);
        assert_eq!(Address::from_string("0.8.1.4").address, 524548u32);
        assert_eq!(Address::from_string("255.255.255.255").address, 4294967295u32);
        assert_eq!(Address::from_string("255.0.0.0").address, 4278190080u32);
    }

    #[test]
    fn test_address_dotted_decimal() {
        for ip in ["0.0.0.0", "1.2.3.4", "0.8.1.4", "255.255.255.255", "255.0.0.0"] {
            let address = Address::from_string(ip);
            assert_eq!(int_to_dotted_decimal(&address.address), address.dotted_decimal());
        }
    }

    #[test]
    fn test_mask_from_cidr() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask = 0xffffffff << shift;
            assert_eq!(Mask::from_cidr(32-shift).address, mask);
        }
    }

    #[test]
    fn test_mask_from_string_and_cidr() {
        assert_eq!(Mask::from_dotted_decimal("0.0.0.0"), Mask::from_cidr(0));
        assert_eq!(Mask::from_dotted_decimal("255.255.255.0"), Mask::from_cidr(24));
        assert_eq!(Mask::from_dotted_decimal("255.255.0.0"), Mask::from_cidr(16));
        assert_eq!(Mask::from_dotted_decimal("255.255.255.255"), Mask::from_cidr(32));
        assert_eq!(Mask::from_dotted_decimal("255.255.255.254"), Mask::from_cidr(31));
    }

    #[test]
    fn test_mask_dotted_decimal() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask: u32 = 0xffffffff << shift;
            assert_eq!(Mask::from_cidr(32-shift).dotted_decimal(), int_to_dotted_decimal(&mask));
        }
    }

    #[test]
    fn test_mask_to_cidr() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask: u32 = 0xffffffff << shift;
            assert_eq!(Mask::from_cidr(32 - shift).to_cidr(), int_to_cidr(&mask, 0));
        }
    }

    #[test]
    fn test_mask_wildcard() {
        for shift in 0..32u8 {
            // Make all 1 through 32 masks by bitwise shifting down from 32 CIDR (0xffffffff)
            let mask: u32 = 0xffffffff << shift;
            assert_eq!(Mask::from_cidr(32 - shift).to_wildcard(), int_to_dotted_decimal(&!mask));
        }
    }

    #[test]
    #[should_panic]
    fn test_mask_invalid() {
        Mask::from_dotted_decimal("255.255.0.255");
    }

    #[test]
    #[should_panic]
    fn test_mask_invalid_cidr() {
        Mask::from_cidr(33);
    }

    #[test]
    fn test_default_cidr_mask() {
        assert_eq!(Address::from_string("0.0.0.1").get_default_class_cidr(), 8);
        assert_eq!(Address::from_string("127.255.255.255").get_default_class_cidr(), 8);
        assert_eq!(Address::from_string("128.0.0.0").get_default_class_cidr(), 16);
        assert_eq!(Address::from_string("191.255.255.255").get_default_class_cidr(), 16);
        assert_eq!(Address::from_string("192.0.0.0").get_default_class_cidr(), 24);
        assert_eq!(Address::from_string("223.255.255.255").get_default_class_cidr(), 24);
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_zeros() {
        Address::from_string("0.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_start() {
        Address::from_string("224.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_d_class_end() {
        Address::from_string("239.255.255.255").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_start() {
        Address::from_string("240.0.0.0").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_e_class_end() {
        Address::from_string("255.255.255.254").get_default_class_cidr();
    }

    #[test]
    #[should_panic]
    fn test_default_cidr_mask_broadcast() {
        Address::from_string("255.255.255.255").get_default_class_cidr();
    }

    #[test]
    fn test_network() {
        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(24);
        let network = Network::new(address, mask);

        assert_eq!(address.address, network.ip.address);
        assert_eq!(mask.address, network.mask.address);
        assert_eq!("192.0.2.0", network.network.to_string());
        assert_eq!("192.0.2.255", network.broadcast.to_string());

        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(32);
        let network = Network::new(address, mask);

        assert_eq!(address.address, network.ip.address);
        assert_eq!(mask.address, network.mask.address);
        assert_eq!("192.0.2.2", network.network.to_string());
        assert_eq!("192.0.2.2", network.broadcast.to_string());
    }

    #[test]
    fn test_network_from_string_cidr() {
        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(24);
        let network = Network::from_string_cidr("192.0.2.2", 24);

        assert_eq!(address.address, network.ip.address);
        assert_eq!(mask.address, network.mask.address);
        assert_eq!("192.0.2.0", network.network.to_string());
        assert_eq!("192.0.2.255", network.broadcast.to_string());

        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(32);
        let network = Network::from_string_cidr("192.0.2.2", 32);

        assert_eq!(address.address, network.ip.address);
        assert_eq!(mask.address, network.mask.address);
        assert_eq!("192.0.2.2", network.network.to_string());
        assert_eq!("192.0.2.2", network.broadcast.to_string());
    }

    #[test]
    fn test_network_first_address() {
        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(24);
        let network = Network::new(address, mask);

        assert_eq!("192.0.2.1", network.get_first_address().to_string());

        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(32);
        let network = Network::new(address, mask);

        assert_eq!("192.0.2.2", network.get_first_address().to_string());
    }

    #[test]
    fn test_network_last_address() {
        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(24);
        let network = Network::new(address, mask);

        assert_eq!("192.0.2.254", network.get_last_address().to_string());

        let address = Address::from_string("192.0.2.2");
        let mask = Mask::from_cidr(32);
        let network = Network::new(address, mask);

        assert_eq!("192.0.2.2", network.get_last_address().to_string());
    }

    #[test]
    fn test_network_usable_hosts() {
        let network = Network::from_string_cidr("192.0.2.2", 24);
        assert_eq!(network.get_usable_hosts(), 254);
        let network = Network::from_string_cidr("192.0.2.2", 30);
        assert_eq!(network.get_usable_hosts(), 2);
        let network = Network::from_string_cidr("192.0.2.2", 31);
        assert_eq!(network.get_usable_hosts(), 2);
        let network = Network::from_string_cidr("192.0.2.2", 32);
        assert_eq!(network.get_usable_hosts(), 1);
    }

    #[test]
    fn test_network_is_host() {
        let network = Network::from_string_cidr("192.0.2.2", 0);
        assert_eq!(network.is_host(), false);
        let network = Network::from_string_cidr("192.0.2.2", 30);
        assert_eq!(network.is_host(), false);
        let network = Network::from_string_cidr("192.0.2.2", 31);
        assert_eq!(network.is_host(), false);
        let network = Network::from_string_cidr("192.0.2.2", 32);
        assert_eq!(network.is_host(), true);
    }

    #[test]
    fn test_network_is_p2p() {
        let network = Network::from_string_cidr("192.0.2.2", 0);
        assert_eq!(network.is_p2p(), false);
        let network = Network::from_string_cidr("192.0.2.2", 30);
        assert_eq!(network.is_p2p(), false);
        let network = Network::from_string_cidr("192.0.2.2", 31);
        assert_eq!(network.is_p2p(), true);
        let network = Network::from_string_cidr("192.0.2.2", 32);
        assert_eq!(network.is_p2p(), false);
    }
}
