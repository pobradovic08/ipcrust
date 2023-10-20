use std::fmt::{Display, Formatter};
use std::num::ParseIntError;

/// Represents the different formats for displaying an IPv6 address.
///
/// - `FormatShort`: Short format, omitting leading zeros in each segment.
/// - `FormatCondensed`: Condensed format, using double colons (::) for consecutive zeros.
/// - `FormatFull`: Full format, with leading zeros in each segment.
#[allow(dead_code)]
pub enum AddressFormat {
    FormatShort = 1,
    FormatCondensed = 2,
    FormatFull = 3,
}

/// This struct represents an IPv6 address.
///
/// It contains the following fields:
/// - address: The numerical representation of the IPv6 address.
/// - class: The class of the IPv6 address.
#[derive(Copy, Clone, PartialEq)]
pub struct AddressV6 {
    address: u128,
    class: AddressClassV6,
}

impl AddressV6 {

    /// Parses an IPv6 address from a string.
    ///
    /// # Arguments
    /// * `input` - A string slice that holds the IPv6 address.
    ///
    /// # Returns
    /// Returns a Result containing the parsed `AddressV6` if successful,
    /// or an `AddresskV6Error` if the input string is not a valid IPv6 address.
    pub fn from_string(input: &str) -> Result<AddressV6, AddressV6Error> {

        // Initialize default values
        // Set all bits for IPv6 to 0 to allow bitwise manipulation
        let mut ipv6_num = 0u128;
        // Create vector of strings that will hold eight 16bit parts of the IPv6 address
        let mut ip_parts: Vec<&str> = Vec::new();

        // If there is double colon split the input string in two parts
        let string_parts = &input.split("::").collect::<Vec<&str>>()[..];
        match string_parts.len() {
            // No double colon compression
            1 => {
                ip_parts = input.split(":").collect::<Vec<&str>>();
            }
            // Double colon compression
            2 => {
                // Left and right parts
                // <part_a>::<part_b>
                let mut part_a: Vec<&str> = Vec::new();
                let mut part_b: Vec<&str> = Vec::new();

                // Match parts to figure out where the double colon is
                match string_parts {
                    // Both parts are empty -> Zero address (::)
                    // Return zero address immediately
                    ["", ""] => {
                        return Ok(AddressV6 { address: 0, class: AddressClassV6::ZERO });
                    }

                    // Double colon in front of the address
                    // Collect individual parts of the `part_b` to Vec<&str>
                    // Prepend 0 parts until all 8 parts are present in `ip_parts`
                    ["", b] => {
                        part_b = b.split(":").collect::<Vec<&str>>();
                        for _ in 0..(8 - part_b.len()) {
                            part_a.push("0");
                        }
                    }
                    // Double colon in the end of the address
                    // Collect individual parts of the `part_a` to Vec<&str>
                    // Append 0 parts until all 8 parts are present in `ip_parts`
                    [a, ""] => {
                        part_a = a.split(":").collect::<Vec<&str>>();
                        for _ in 0..(8 - part_a.len()) {
                            part_b.push("0");
                        }
                    }
                    // Double colon in the middle of the address
                    // Collect individual parts of the `part_a` and `part_b` to Vec<&str>
                    // Insert 0 parts in the middle until whole 8 parts is present in `ip_parts`
                    _ => {
                        part_a = string_parts[0].split(":").collect::<Vec<&str>>();
                        part_b = string_parts[1].split(":").collect::<Vec<&str>>();
                        for _ in 0..(8 - (part_a.len() + part_b.len())) {
                            part_a.push("0");
                        }
                    }
                }

                // Combine both parts to `ip_parts` to prepare for conversion to decimal
                ip_parts.append(&mut part_a);
                ip_parts.append(&mut part_b);
            }
            // More than one double colon
            _ => return Err(AddressV6Error::InvalidAddress)
        }

        // Parse hexadecimal string to u16.
        // Collect to `Result<Vec<u32>, ParseIntError>` instead of just Vec<u16>
        // Providing invalid IPv6 string that can't be parsed (ParseIntError)
        // will result in AddressV6Error
        let ipv6_parts = ip_parts.iter().map(
            |x| u16::from_str_radix(x, 16)
        ).collect::<Result<Vec<u16>,ParseIntError>>();

        // Match ipv6_parts
        // If the Result is OK and the length of the parts is 8, build IPv6 from parts
        // If there is an Error or the length of the parts is not 8, return AddressV6Error
        match ipv6_parts {
            Ok(vector) => {
                if vector.len() == 8 {
                    // Go through 8 parts in `vector`, converting them to u128,
                    // shifting them 16bits at the time to 'position' them to correct place,
                    // and adding the result to `ipv6_num` that represents the IPv6 address
                    // ipv6_parts example: [1, 2, 3, 4, 5, 6, 7, 8]
                    // 0000 0000 0000 0000 0000 0000 0000 0001 << shift 112 bits
                    // 0000 0000 0000 0000 0000 0000 0000 0002 << shift 96 bits
                    // 0000 0000 0000 0000 0000 0000 0000 0003 << shift 80 bits
                    // ...
                    for i in 1..=8 {
                        ipv6_num += (vector[i - 1] as u128) << 128 - (i * 16);
                    }
                    return Ok(AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) })
                }
                Err(AddressV6Error::InvalidAddress)
            },
            Err(_e) => Err(AddressV6Error::InvalidAddress)
        }
    }

    /// This function returns a string representation of the IPv6 address.
    ///
    /// # Arguments
    /// * `format` - An `AddressFormat` enum value that specifies the format of the output string.
    ///
    /// # Example
    /// ```
    /// let string = address.to_string(AddressFormat::FormatShort);
    /// ```
    pub fn to_string(&self, format: AddressFormat) -> String {
        // Initialize array of all zeros (for further bitwise transformation)
        let mut hex_parts: [u16; 8] = [0; 8];
        let string: String;

        // Shift the address incrementally for 16 bits
        // and store the least significant 16bits (0xffff) for each shift to its part of the array
        for i in 1..=8 {
            hex_parts[i - 1] = (self.address >> (128 - i * 16) & 0xffff) as u16;
        }

        match format {
            AddressFormat::FormatShort => {
                /*
                Find the longest contiguous occurrence of 0 parts
                `p` and `p_tmp` are the tuples that hold (0: end_position, 1: length)
                `p` represents the longest contiguous occurrence
                `p_tmp` represents the temporary counter

                             p.1 = 3
                              |---|
                1234:0:0:1234:0:0:0:1234
                                  ^
                               p.0 = 7
                */

                // Longest occurrence
                let mut p: (usize, usize) = (0, 0);
                // Temporary counter
                let mut p_tmp: (usize, usize) = (0, 0);

                // Go through all 8 IPv6 address parts
                for i in 0..8 {
                    // If a part iz zero, set the position of temporary counter to current index
                    // and increase the length value of temporary counter by 1
                    if hex_parts[i] == 0 {
                        p_tmp.0 = i;
                        p_tmp.1 += 1;
                    } else {
                        // If temporary counter length is greater than current maximum length
                        // save the temporary counter as maximum and reset the temporary counter
                        if p_tmp.1 > p.1 {
                            p = p_tmp;
                            p_tmp.1 = 0;
                            p_tmp.0 = 0;
                        }
                    }
                }

                // Save the temporary counter as maximum
                if p_tmp.1 > p.1 {
                    p = p_tmp;
                }

                // Start index is end position minus the length of null parts
                let start = 1 + p.0 - p.1;
                let end = p.0 + 1;

                /*
                [1234, 0, 0, 1234, 0, 0, 0, 1234]
                 |--------------|           |--|
                       start                 end
                 */
                let p1 = &hex_parts[0..start];
                let p2 = &hex_parts[end..];

                // Convert u16s to hex strings
                let s1 = p1.iter().map(|h| format!("{:x}", h)).collect::<Vec<String>>();
                let s2 = p2.iter().map(|h| format!("{:x}", h)).collect::<Vec<String>>();

                // If there are 8 parts use colon as a separator between s1 and s2 instead of double colon
                let separator: &str = if s1.len() + s2.len() == 8 {
                    ":"
                } else {
                    "::"
                };

                // Join two parts
                string = format!("{}{}{}", s1.join(":"), separator, s2.join(":"));
            }
            AddressFormat::FormatCondensed => {
                let string_array = hex_parts.map(|h| format!("{:x}", h));
                string = string_array.join(":");
            }
            AddressFormat::FormatFull => {
                let string_array = hex_parts.map(|h| format!("{:04x}", h));
                string = string_array.join(":");
            }
        }

        // Return generated string
        string
    }

    ///
    /// Truncate IPv6 address to last 64bits (Interface ID)
    ///
    fn get_eui64_num(&self) -> u64 {
        self.address as u64
    }

    ///
    /// Generate EUI-64 string in `aaaa:bbbb:cccc:dddd` format
    ///
    pub fn get_eui64_string(&self) -> String {
        let eui64_num = self.get_eui64_num();

        let mut hex_parts: [u32; 4] = [0; 4];

        for i in 1..=4 {
            hex_parts[i - 1] = (eui64_num >> (64 - i * 16) & 0xffff) as u32;
        }

        let string_array = hex_parts.map(|h| format!("{:04x}", h));
        string_array.join(":")
    }

    ///
    /// Return `true` if the Interface ID part of the IPv6 address has the bits
    /// indicative of EUI-64 set.
    /// ```
    /// 0000001000000000000000001111111111111110000000000000000000000000
    ///       ^                 ^--------------^
    /// Universal bit                0xfffe
    /// ```
    ///
    pub fn is_eui64(&self) -> bool {
        let eui64_mask: u64 = 0x20000fffe000000;
        self.get_eui64_num() & eui64_mask == eui64_mask
    }

    ///
    /// Calculate the EUI-48 (MAC Address) that was used for generating EUI-64
    /// 1. Invert the U/L bit
    /// 2. Remove 0xfffe (the 24 through 48 bits)
    ///
    fn get_eui48_num(&self) -> u64 {
        // 0b0000001000000000000000000000000000000000000000000000000000000000
        let eui48_flip_mask = 0x200000000000000;
        // Flip the U/L bit (XOR)
        let flipped = self.get_eui64_num() ^ eui48_flip_mask;

        // Shift everything by 16 bits and set last 24 bits to zero
        let part_1 = (flipped >> 16) & 0xffffff000000;
        // Restore last 24 bits
        let part_2 = flipped & 0xffffff;

        part_1 + part_2
    }

    ///
    /// Generate EUI-48 string (MAC address) in `aa:bb:cc:dd:ee:ff` format
    ///
    pub fn get_eui48_string(&self) -> String {
        let eui48_num = self.get_eui48_num();

        let mut hex_parts: [u32; 6] = [0; 6];
        for i in 1..=6 {
            hex_parts[i - 1] = (eui48_num >> (48 - i * 8) & 0xff) as u32;
        }

        let string_array = hex_parts.map(|h| format!("{:02x}", h));
        string_array.join(":")
    }
}

impl Display for AddressV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string(AddressFormat::FormatFull))
    }
}

/// Represents the possible errors that can occur during IPv6 address parsing.
///
/// - `InvalidAddress`: Indicates that the address string is not a valid IPv6 address.
#[derive(Debug, PartialEq)]
pub enum AddressV6Error {
    InvalidAddress
}

/// This enum represents the possible errors that can occur during network parsing.
///
/// - InvalidAddress: Indicates that the address in the network string is invalid.
/// - InvalidCidr: Indicates that the CIDR value in the network string is invalid.
#[derive(Debug, PartialEq)]
pub enum NetworkV6Error {
    InvalidAddress,
    InvalidCidr
}

/// This struct represents an IPv6 network.
///
/// It contains the following fields:
/// - address: The IPv6 address of the network.
/// - cidr: The CIDR notation of the network.
#[derive(PartialEq)]
pub struct NetworkV6 {
    ip: AddressV6,
    cidr: u8,
    _mask: u128,
}

impl NetworkV6 {

    pub fn from_string(ip_str: &str) -> Result<NetworkV6, NetworkV6Error>  {
        let parts: Vec<&str> = ip_str.split(|c| c == '/').collect();
        let mask: u128;
        let cidr: u8;
        match parts.len() {
            // <part[0]>/<part[1]>
            2 => {
                //Try to parse CIDR as `u8`
                match parts[1].parse::<u8>() {
                    Ok(v) => {
                        if v > 128 {
                            return Err(NetworkV6Error::InvalidCidr);
                        }
                        cidr = v;
                        mask = NetworkV6::cidr_to_mask(v);
                    }
                    Err(_) => {
                        return Err(NetworkV6Error::InvalidCidr);
                    }
                }
                match AddressV6::from_string(parts[0]) {
                    Ok(ip) => {
                        Ok(NetworkV6 { ip, _mask: mask, cidr })
                    },
                    Err(_e) => Err(NetworkV6Error::InvalidAddress)
                }
            }
            _ => {
                Err(NetworkV6Error::InvalidAddress)
            }
        }
    }

    pub fn get_first_address(&self) -> AddressV6 {
        let ipv6_num: u128 = self.ip.address & self._mask;
        return AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) };
    }

    pub fn get_last_address(&self) -> AddressV6 {
        let ipv6_num: u128 = self.ip.address | (!self._mask);
        return AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) };
    }

    #[allow(dead_code)]
    pub fn contains(&self, ip: AddressV6) -> bool {
        return self.get_first_address().address <= ip.address && ip.address <= self.get_last_address().address;
    }

    pub fn print_short(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatShort), self.cidr)
    }

    #[allow(unused)]
    pub fn print_condensed(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatCondensed), self.cidr)
    }

    #[allow(unused)]
    pub fn print_full(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatFull), self.cidr)
    }

    fn cidr_to_mask(cidr: u8) -> u128 {
        match cidr {
            0 => 0,
            _ => u128::MAX << (128 - cidr)
        }
    }
}

impl Display for NetworkV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.print_short())
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum AddressClassV6 { ZERO, UNICAST, MULTICAST }

impl AddressClassV6 {
    fn get(ip: u128) -> AddressClassV6 {
        return if ip == 0 {
            AddressClassV6::ZERO
        } else if (ip >> 120) == 0xff {
            AddressClassV6::MULTICAST
        } else {
            AddressClassV6::UNICAST
        };
    }

    fn get_additional_info(address: AddressV6) -> Vec<String> {
        let n = |network: &str, cidr: u8| NetworkV6::from_string(format!("{}/{}", network, cidr).as_str()).unwrap();
        let mut info_array: Vec<String> = vec!();

        let address_info_map: [(NetworkV6, &str); 20] = [
            (n("::1", 128), "Loopback Address - RFC4291"),
            (n("::", 128), "Unspecified Address - RFC4291"),
            (n("::ffff:0:0", 96), "IPv4-mapped Address - RFC4291"),
            (n("64:ff9b::", 96), "IPv4-IPv6 Translat. - RFC6052"),
            (n("64:ff9b:1::", 48), "IPv4-IPv6 Translat. - RFC8215"),
            (n("100::", 64), "Discard-Only Address Block - RFC6666"),
            (n("2001::", 23), "IETF Protocol Assignments - RFC2928"),
            (n("2001::", 32), "TEREDO - RFC4380, RFC8190"),
            (n("2001:1::1", 128), "Port Control Protocol Anycast - RFC7723"),
            (n("2001:1::2", 128), "Traversal Using Relays around NAT Anycast - RFC8155"),
            (n("2001:2::", 48), "Benchmarking - RFC5180"),
            (n("2001:3::", 32), "AMT - RFC7450"),
            (n("2001:4:112::", 48), "AS112v6 - RFC7535"),
            (n("2001:20::", 28), "ORCHIDv2 - RFC7343"),
            (n("2001:30::", 28), "Drone Remote ID Protocol Entity Tags (DETs) Prefix - RFC9374"),
            (n("2001:db8::", 32), "Documentation - RFC3849"),
            (n("2002::", 16), "6to4 - RFC3056"),
            (n("2620:4f:8000::", 48), "Direct Delegation AS112 Service - RFC7534"),
            (n("fc00::", 7), "Unique-Local - RFC4193, RFC8190"),
            (n("fe80::", 10), "Link-Local Unicast - RFC4291"),
        ];

        for (network, note) in address_info_map {
            if network.contains(address) {
                info_array.push(String::from(note))
            }
        }

        info_array
    }
}

impl Display for AddressClassV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressClassV6::ZERO => write!(f, "Unspecified IPv6 address"),
            AddressClassV6::MULTICAST => write!(f, "Multicast IPv6 address"),
            AddressClassV6::UNICAST => write!(f, "Unicast IPv6 address")
        }
    }
}

fn print_bar_colored(cidr: u8) -> String {
    let position = cidr as usize / 4;
    let padding = position / 4;
    let bars = "▄▄▄▄ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄ ▄▄▄▄".chars().collect::<Vec<char>>();
    let part_1 = &bars[..(position + padding)].iter().collect::<String>();
    let part_2 = &bars[(position + padding)..].iter().collect::<String>();
    format!("\x1b[38;5;92m{}\x1b[38;5;214m{}\x1b[0m", part_1, part_2)
}

fn print_bar_ipv6_parts(cidr: u8) -> String {
    let position = cidr as usize / 4;
    let padding = position / 4;
    let bars = "▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ".chars().collect::<Vec<char>>();
    let part_1 = &bars[..(position + padding)].iter().collect::<String>();
    let part_2 = &bars[(position + padding)..].iter().collect::<String>();
    format!("\x1b[38;5;198m{}\x1b[38;5;38m{}\x1b[0m▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀", part_1, part_2)
}

pub fn print_results(net: &NetworkV6) {
    let tw = 71;
    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<1$}│", format!("\x1b[1;38;5;10m █ Address:    {}\x1b[0m", net.ip), tw + 14);
    println!("│{0:<1$}│", format!("\x1b[0;38;5;38m ░ Type:       {}\x1b[0m", net.ip.class), tw + 14);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<1$}│", format!(" ░ Network:    {}", net), tw - 2);
    println!("│{0:<1$}│", format!(" ░ First IPv6: {}", net.get_first_address()), tw - 2);
    println!("│{0:<1$}│", format!(" ░ Last IPv6:  {}", net.get_last_address()), tw - 2);
    println!("│{:^1$}│", "", tw - 2);
    if net.ip.is_eui64() {
        println!("│{:<1$}│", "\x1b[1m ░ Address might be autoassigned:\x1b[0m", tw + 6);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-64:     {}", net.ip.get_eui64_string()), tw - 2);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-48:     {}", net.ip.get_eui48_string()), tw - 2);
        println!("│{:^1$}│", "", tw - 2);
    }

    for note in AddressClassV6::get_additional_info(net.ip) {
        println!("│{:<1$}│", format!("\x1b[38;5;198m ░ Note: {}.\x1b[0m", note), tw + 13);
    }

    if net.cidr < 128 {
        println!("├{:─^1$}┤", "", tw - 2);
        println!("│{:^1$}│", "", tw - 2);
        if net.cidr == 64 {
            println!("│{:^1$}│", "\x1b[38;5;198m Prefix/Subnet    \x1b[0m \x1b[0m Interface identifier\x1b[0m", tw + 21);
            println!("│{:^1$}│", print_bar_ipv6_parts(net.cidr), tw + 23);
        } else if net.cidr < 64 {
            println!("│{:^1$}│", "\x1b[38;5;198m Prefix \x1b[38;5;38m Subnet ID\x1b[0m \x1b[0m Interface identifier\x1b[0m", tw + 31);
            println!("│{:^1$}│", print_bar_ipv6_parts(net.cidr), tw + 23);
        }

        println!("│{0:^1$}│", format!("\x1b[1m{}\x1b[0m", net.ip), tw + 6);

        println!("│{:^1$}│", print_bar_colored(net.cidr), tw + 23);
        println!("│{:^1$}│", "\x1b[38;5;92m Network part                \x1b[38;5;214m Hosts part \x1b[0m", tw + 23);
        println!("│{:^1$}│", "", tw - 2);
    }
    println!("└{:─^1$}┘", "", tw - 2);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_class() {
        let n = |address: &str| AddressClassV6::get(AddressV6::from_string(address).unwrap().address);

        assert_eq!(n("::"), AddressClassV6::ZERO);
        assert_eq!(n("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AddressClassV6::UNICAST);
        assert_eq!(n("ff00:0000:0000:0000:0000:0000:0000:0000"), AddressClassV6::MULTICAST);
        assert_eq!(n("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AddressClassV6::MULTICAST);
        assert_eq!(n("2001:0db8:85a3::8a2e:0370:7334"), AddressClassV6::UNICAST);
    }

    #[test]
    fn test_address_v6_from_string() {
        let address = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334").unwrap();
        assert_eq!(address.address, 42540766452641154071740215577757643572);

        let address = AddressV6::from_string("2001:0db8:85a3::0:0:8a2e:0370:7334").unwrap();
        assert_eq!(address.address, 42540766452641154071740215577757643572);

        let address = AddressV6::from_string("2001:0db8:85a3::").unwrap();
        assert_eq!(address.address, 42540766452641154071740063647526813696);

        let address = AddressV6::from_string("::8a2e:0370:7334").unwrap();
        assert_eq!(address.address, 151930230829876);
    }

    #[test]
    fn test_address_v6_to_string_condensable() {
        let address = AddressV6 {
            address: 42540766452641154071740215577757643572,
            class: AddressClassV6::UNICAST,
        };
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:0:0:8a2e:370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334");

        let address = AddressV6 {
            address: 42540766452641154081696963253260779520,
            class: AddressClassV6::UNICAST,
        };
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0000:8a2e:0370:0000:0000");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:0:8a2e:370:0:0");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3:0:8a2e:370::");
    }

    #[test]
    fn test_address_v6_to_string_uncondensable() {
        let address = AddressV6 {
            address: 42540766452641154090187522601420616500,
            class: AddressClassV6::UNICAST,
        };
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0001:0002:8a2e:0370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:1:2:8a2e:370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3:1:2:8a2e:370:7334");
    }

    #[test]
    fn test_address_v6_display_format() {
        let address = AddressV6 {
            address: 42540766452641154071740215577757643572,
            class: AddressClassV6::UNICAST,
        };

        assert_eq!(format!("{}", address), address.to_string(AddressFormat::FormatFull));
        assert_eq!(format!("{}", address), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }

    #[test]
    fn test_network_v6_new_64() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.cidr, 64);
        assert_eq!(network.ip.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334")
    }

    #[test]
    fn test_network_v6_new_128() {
        let network = NetworkV6::from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128").unwrap();
        assert_eq!(network.cidr, 128);
        assert_eq!(network.ip.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334")
    }

    #[test]
    fn test_network_v6_contains_zero() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/0").unwrap();
        let test_ip = AddressV6::from_string("::").unwrap();
        assert_eq!(network.contains(test_ip), true);
        let test_ip = AddressV6::from_string("2001:0db8:85a3::").unwrap();
        assert_eq!(network.contains(test_ip), true);
        let test_ip = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(network.contains(test_ip), true);
    }

    #[test]
    fn test_network_v6_contains_64() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        let test_ip = AddressV6::from_string("2001:0db8:85a3::").unwrap();
        assert_eq!(network.contains(test_ip), true);
        let test_ip = AddressV6::from_string("2001:0db8:85a3:0000:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(network.contains(test_ip), true);
    }

    #[test]
    fn test_network_v6_contains_127() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/127").unwrap();

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334").unwrap();
        assert_eq!(network.contains(test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7335").unwrap();
        assert_eq!(network.contains(test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7336").unwrap();
        assert_eq!(network.contains(test_ip), false);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7333").unwrap();
        assert_eq!(network.contains(test_ip), false);
    }

    #[test]
    fn test_network_v6_contains_128() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/128").unwrap();
        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334").unwrap();
        assert_eq!(network.contains(test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7335").unwrap();
        assert_eq!(network.contains(test_ip), false);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7333").unwrap();
        assert_eq!(network.contains(test_ip), false);
    }

    #[test]
    fn test_network_v6_get_first_address_zero() {
        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0").unwrap();
        assert_eq!(network.get_first_address().address, 0);
    }

    #[test]
    fn test_network_v6_get_first_address_64() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.get_first_address().address, 42540766452641154071740063647526813696);

        let network = NetworkV6::from_string("::/64").unwrap();
        assert_eq!(network.get_first_address().address, 0);

        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/64").unwrap();
        assert_eq!(network.get_first_address().address, 340282366920938463444927863358058659840);
    }

    #[test]
    fn test_network_v6_get_first_address_127() {
        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127").unwrap();
        assert_eq!(network.get_first_address().address, 340282366920938463463374607431768211454);
    }

    #[test]
    fn test_network_v6_get_first_address_128() {
        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap();
        assert_eq!(network.get_first_address().address, 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_zero() {
        let network = NetworkV6::from_string("::/0").unwrap();
        assert_eq!(network.get_last_address().address, 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_64() {
        let network = NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.get_last_address().address, 42540766452641154090186807721236365311);
    }

    #[test]
    fn test_network_v6_get_last_address_127() {
        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127").unwrap();
        assert_eq!(network.get_last_address().address, 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_128() {
        let network = NetworkV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap();
        assert_eq!(network.get_last_address().address, 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_invalid_input() {
        // Test with an invalid IPv6 address
        assert!(matches!(
            NetworkV6::from_string("invalid_address/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));
        assert!(matches!(
            NetworkV6::from_string("abcd:efgh::/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));
        assert!(matches!(
            NetworkV6::from_string("1:1:1:1:1::1:1/1/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));

        // One octet above
        assert!(matches!(
            NetworkV6::from_string("1:1:1:1:1:1:1:1:1/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));
        // One octet short
        assert!(matches!(
            NetworkV6::from_string("1:1:1:1:1:1:1/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));
        // Last octet overflows
        assert!(matches!(
            NetworkV6::from_string("1:1:1:1:1:1:1:fffff/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));
        // Two double colons
        assert!(matches!(
            NetworkV6::from_string("1::1:1::1:1:1/64"),
            Err(NetworkV6Error::InvalidAddress)
        ));

        // Test with an invalid CIDR value
        assert!(matches!(
            NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/129"),
            Err(NetworkV6Error::InvalidCidr)
        ));
        assert!(matches!(
            NetworkV6::from_string("2001:0db8:85a3::8a2e:0370:7334/ab"),
            Err(NetworkV6Error::InvalidCidr)
        ));
    }

    #[test]
    fn test_network_v6_class_display_format() {
        assert_eq!(AddressClassV6::ZERO.to_string(), "Unspecified IPv6 address");
        assert_eq!(AddressClassV6::MULTICAST.to_string(), "Multicast IPv6 address");
        assert_eq!(AddressClassV6::UNICAST.to_string(), "Unicast IPv6 address");
    }

    #[test]
    fn test_network_v6_display_format() {
        let address = AddressV6 {
            address: 42540766452641154071740215577757643572,
            class: AddressClassV6::UNICAST,
        };

        let network = NetworkV6 {
            ip: address,
            cidr: 128,
            _mask: NetworkV6::cidr_to_mask(128)
        };

        let expected_string = format!("{}/{}", address.to_string(AddressFormat::FormatShort), 128);

        assert_eq!(network.to_string(), expected_string);
    }

    #[test]
    fn test_network_v6_display_formats() {
        let address = AddressV6 {
            address: 42540766452641154071740215577757643572,
            class: AddressClassV6::UNICAST,
        };

        let network = NetworkV6 {
            ip: address,
            cidr: 128,
            _mask: NetworkV6::cidr_to_mask(128)
        };

        let expected_string = format!("{}/{}", address.to_string(AddressFormat::FormatShort), 128);
        assert_eq!(network.print_short(), expected_string);

        let expected_string = format!("{}/{}", address.to_string(AddressFormat::FormatCondensed), 128);
        assert_eq!(network.print_condensed(), expected_string);

        let expected_string = format!("{}/{}", address.to_string(AddressFormat::FormatFull), 128);
        assert_eq!(network.print_full(), expected_string);

    }
}
