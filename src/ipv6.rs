use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use regex::Regex;

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

/// This struct represents an IPv6 address with mask (CIDR).
///
/// It contains the following fields:
/// - address: The numerical representation of the IPv6 address.
/// - cidr: The CIDR notation of the network.
/// - class: The class of the IPv6 address.
#[derive(Copy, Clone, PartialEq)]
pub struct AddressV6 {
    address: u128,
    cidr: u8,
    class: AddressClassV6,
    _mask: u128,
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

        // Parse input string to address part and cidr part
        let (address_str, cidr) = AddressV6::_parse_string(input)?;

        // If there is double colon split the input string in two parts
        let string_parts = &address_str.split("::").collect::<Vec<&str>>()[..];
        match string_parts.len() {
            // No double colon compression
            1 => {
                ip_parts = address_str.split(":").collect::<Vec<&str>>();
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
                        return AddressV6::from_dec(0, Some(cidr));
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
                    return AddressV6::from_dec(ipv6_num, Some(cidr));
                }
                Err(AddressV6Error::InvalidAddress)
            },
            Err(_e) => Err(AddressV6Error::InvalidAddress)
        }
    }

    pub fn from_dec(address: u128, cidr: Option<u8>) -> Result<AddressV6, AddressV6Error> {
        let cidr = cidr.unwrap_or(128u8);
        if cidr > 128 {
            return Err(AddressV6Error::InvalidCidr);
        }
        Ok(AddressV6 {
            address,
            cidr,
            class: AddressClassV6::get(address),
            _mask: AddressV6::cidr_to_mask(cidr)
        })
    }

    fn _parse_string(input: &str) -> Result<(&str, u8), AddressV6Error> {
        let parts: Vec<&str> = input.split(|c| c == '/').collect();
        let address: &str = parts[0];
        let regex_address_v6 = Regex::new(r"^([A-Fa-f0-9:]{1,4}:+)+([A-Fa-f0-9]{1,4})?$").unwrap();

        match parts.len() {
            // IP: <part[0]>
            1 => return Ok((address, 128u8)),
            // IP: <part[0]>/<part[1]>
            2 => {
                if !regex_address_v6.is_match(address) {
                    return Err(AddressV6Error::InvalidAddress);
                }

                //Try to parse CIDR as `u8`
                return match parts[1].parse::<u8>() {
                    Ok(cidr) => Ok((address, cidr)),
                    Err(_) => Err(AddressV6Error::InvalidCidr),
                }
            },
            _ => Err(AddressV6Error::InvalidAddress),
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

    pub fn get_first_address(&self) -> u128 {
        self.address & self._mask
    }

    pub fn get_last_address(&self) -> u128 {
        self.address | (!self._mask)
    }

    pub fn contains(&self, ip: &AddressV6) -> bool {
        return self.get_first_address() <= ip.address && ip.address <= self.get_last_address();
    }

    pub fn to_string(&self, format: AddressFormat) -> String {
        AddressV6::dec_to_str(self.address, format)
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

    fn cidr_to_mask(cidr: u8) -> u128 {
        match cidr {
            0 => 0,
            _ => u128::MAX << (128 - cidr)
        }
    }

    fn dec_to_str(address: u128, format: AddressFormat) -> String {
        // Initialize array of all zeros (for further bitwise transformation)
        let mut hex_parts: [u16; 8] = [0; 8];
        let string: String;

        // Shift the address incrementally for 16 bits
        // and store the least significant 16bits (0xffff) for each shift to its part of the array
        for i in 1..=8 {
            hex_parts[i - 1] = (address >> (128 - i * 16) & 0xffff) as u16;
        }

        match format {
            AddressFormat::FormatShort => {
                let (start, end) = AddressV6::find_contiguous_zeros(&hex_parts);

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

    /**
    Find the longest contiguous occurrence of 0 parts
    `location` and `location_tmp` are the tuples that hold (0: end_position, 1: length)
    `location` represents the longest contiguous occurrence
    `location_tmp` represents the temporary counter

               location.1 = 3
                   |---|
     1234:0:0:1234:0:0:0:1234
                       ^
               location.0 = 7
     */
    pub fn find_contiguous_zeros(array: &[u16; 8]) -> (usize, usize) {

        // Longest occurrence
        let mut location: (usize, usize) = (0, 0);
        // Temporary counter
        let mut location_tmp: (usize, usize) = (0, 0);

        // Go through all 8 IPv6 address parts
        for i in 0..8 {
            // If a part iz zero, set the position of temporary counter to current index
            // and increase the length value of temporary counter by 1
            if array[i] == 0 {
                location_tmp.0 = i;
                location_tmp.1 += 1;
            } else {
                // If temporary counter length is greater than current maximum length
                // save the temporary counter as maximum and reset the temporary counter
                if location_tmp.1 > location.1 {
                    location = location_tmp;
                    location_tmp.1 = 0;
                    location_tmp.0 = 0;
                }
            }
        }

        // Save the temporary counter as maximum
        if location_tmp.1 > location.1 {
            location = location_tmp;
        }

        // Start index is end position minus the length of null parts
        let start = 1 + location.0 - location.1;
        let end = location.0 + 1;

        (start, end)
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
/// - InvalidCidr: Indicates that the CIDR value in the network string is invalid.
#[derive(Debug, PartialEq)]
pub enum AddressV6Error {
    InvalidAddress,
    InvalidCidr
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

    fn get_additional_info(address: &AddressV6) -> Vec<String> {
        let n = |network: &str, cidr: u8| AddressV6::from_string(format!("{}/{}", network, cidr).as_str()).unwrap();
        let mut info_array: Vec<String> = vec!();

        let address_info_map: [(AddressV6, &str); 20] = [
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

pub fn print_results(net: &AddressV6) -> () {
    let tw = 71;
    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<1$}│", format!("\x1b[1;38;5;10m █ Address:    {}\x1b[0m", net), tw + 14);
    println!("│{0:<1$}│", format!("\x1b[0;38;5;38m ░ Type:       {}\x1b[0m", net.class), tw + 14);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<1$}│", format!(" ░ Network:    {}/{}", AddressV6::dec_to_str(net.get_first_address(), AddressFormat::FormatFull), net.cidr), tw - 2);
    println!("│{0:<1$}│", format!(" ░ First IPv6: {}", AddressV6::dec_to_str(net.get_first_address(), AddressFormat::FormatFull)), tw - 2);
    println!("│{0:<1$}│", format!(" ░ Last IPv6:  {}", AddressV6::dec_to_str(net.get_last_address(), AddressFormat::FormatFull)), tw - 2);
    println!("│{:^1$}│", "", tw - 2);
    if net.is_eui64() {
        println!("│{:<1$}│", "\x1b[1m ░ Address might be autoassigned:\x1b[0m", tw + 6);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-64:     {}", net.get_eui64_string()), tw - 2);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-48:     {}", net.get_eui48_string()), tw - 2);
        println!("│{:^1$}│", "", tw - 2);
    }

    for note in AddressClassV6::get_additional_info(net) {
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

        println!("│{0:^1$}│", format!("\x1b[1m{}\x1b[0m", net), tw + 6);

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
    fn test_prints() {
        let network = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:2222/64").unwrap();
        assert_eq!(print_results(&network), ());
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/32").unwrap();
        assert_eq!(print_results(&network), ());
    }

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
    fn test_address_v6_from_dec() {
        let address = AddressV6::from_dec(42540766452641154081696963253260779520, Some(128)).unwrap();
        assert_eq!(address.address, 42540766452641154081696963253260779520);
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
        let address = AddressV6::from_dec(42540766452641154071740215577757643572, Some(0)).unwrap();
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:0:0:8a2e:370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334");

        let address = AddressV6::from_dec(42540766452641154081696963253260779520, Some(0)).unwrap();
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0000:8a2e:0370:0000:0000");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:0:8a2e:370:0:0");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3:0:8a2e:370::");
    }

    #[test]
    fn test_address_v6_to_string_uncondensable() {
        let address = AddressV6::from_dec(42540766452641154090187522601420616500, Some(0)).unwrap();
        assert_eq!(address.to_string(AddressFormat::FormatFull), "2001:0db8:85a3:0001:0002:8a2e:0370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatCondensed), "2001:db8:85a3:1:2:8a2e:370:7334");
        assert_eq!(address.to_string(AddressFormat::FormatShort), "2001:db8:85a3:1:2:8a2e:370:7334");
    }

    #[test]
    fn test_address_v6_display_format() {
        let address = AddressV6::from_dec(42540766452641154071740215577757643572, Some(0)).unwrap();

        assert_eq!(format!("{}", address), address.to_string(AddressFormat::FormatFull));
        assert_eq!(format!("{}", address), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }

    #[test]
    fn test_address_v6_is_eui_64() {
        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:2222").unwrap();
        assert_eq!(address.is_eui64(), true);
        let address = AddressV6::from_string("2001:0db8:85a3:0:0:11ff:fe11:2222").unwrap();
        assert_eq!(address.is_eui64(), false);
    }

    #[test]
    fn test_address_v6_get_eui_64_string(){
        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:2222").unwrap();
        assert_eq!(address.get_eui64_string(), "0200:11ff:fe11:2222");

        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:0").unwrap();
        assert_eq!(address.get_eui64_string(), "0200:11ff:fe11:0000");
    }

    #[test]
    fn test_address_v6_get_eui_64_dec(){
        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:2222").unwrap();
        assert_eq!(address.get_eui64_num(), 144134979252724258);

        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:0").unwrap();
        assert_eq!(address.get_eui64_num(), 144134979252715520);
    }

    #[test]
    fn test_address_v6_get_eui_48_string() {
        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11ff:fe11:2222").unwrap();
        assert_eq!(address.get_eui48_string(), "00:00:11:11:22:22");
    }

    #[test]
    fn test_address_v6_get_eui_48_dec() {
        let address = AddressV6::from_string("2001:0db8:85a3:0:200:11FF:FE11:2222").unwrap();
        assert_eq!(address.get_eui48_num(), 286335522)
    }

    #[test]
    fn test_network_v6_new_64() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.cidr, 64);
        assert_eq!(network.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334")
    }

    #[test]
    fn test_network_v6_new_128() {
        let network = AddressV6::from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128").unwrap();
        assert_eq!(network.cidr, 128);
        assert_eq!(network.to_string(AddressFormat::FormatShort), "2001:db8:85a3::8a2e:370:7334")
    }

    #[test]
    fn test_network_v6_contains_zero() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/0").unwrap();
        let test_ip = AddressV6::from_string("::").unwrap();
        assert_eq!(network.contains(&test_ip), true);
        let test_ip = AddressV6::from_string("2001:0db8:85a3::/0").unwrap();
        assert_eq!(network.contains(&test_ip), true);
        let test_ip = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0").unwrap();
        assert_eq!(network.contains(&test_ip), true);
    }

    #[test]
    fn test_network_v6_contains_64() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        let test_ip = AddressV6::from_string("2001:0db8:85a3::/64").unwrap();
        assert_eq!(network.contains(&test_ip), true);
        let test_ip = AddressV6::from_string("2001:0db8:85a3:0000:ffff:ffff:ffff:ffff/64").unwrap();
        assert_eq!(network.contains(&test_ip), true);
    }

    #[test]
    fn test_network_v6_contains_127() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/127").unwrap();

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334").unwrap();
        assert_eq!(network.contains(&test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7335").unwrap();
        assert_eq!(network.contains(&test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7336").unwrap();
        assert_eq!(network.contains(&test_ip), false);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7333").unwrap();
        assert_eq!(network.contains(&test_ip), false);
    }

    #[test]
    fn test_network_v6_contains_128() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/128").unwrap();
        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334").unwrap();
        assert_eq!(network.contains(&test_ip), true);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7335").unwrap();
        assert_eq!(network.contains(&test_ip), false);

        let test_ip = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7333").unwrap();
        assert_eq!(network.contains(&test_ip), false);
    }

    #[test]
    fn test_network_v6_get_first_address_zero() {
        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0").unwrap();
        assert_eq!(network.get_first_address(), 0);
    }

    #[test]
    fn test_network_v6_get_first_address_64() {

        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.get_first_address(), 42540766452641154071740063647526813696);

        let network = AddressV6::from_string("::/64").unwrap();
        assert_eq!(network.get_first_address(), 0);

        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/64").unwrap();
        assert_eq!(network.get_first_address(), 340282366920938463444927863358058659840);
    }

    #[test]
    fn test_network_v6_get_first_address_127() {
        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127").unwrap();
        assert_eq!(network.get_first_address(), 340282366920938463463374607431768211454);
    }

    #[test]
    fn test_network_v6_get_first_address_128() {
        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap();
        assert_eq!(network.get_first_address(), 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_zero() {
        let network = AddressV6::from_string("::/0").unwrap();
        assert_eq!(network.get_last_address(), 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_64() {
        let network = AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/64").unwrap();
        assert_eq!(network.get_last_address(), 42540766452641154090186807721236365311);
    }

    #[test]
    fn test_network_v6_get_last_address_127() {
        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127").unwrap();
        assert_eq!(network.get_last_address(), 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_get_last_address_128() {
        let network = AddressV6::from_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap();
        assert_eq!(network.get_last_address(), 340282366920938463463374607431768211455);
    }

    #[test]
    fn test_network_v6_invalid_input() {
        // Test with an invalid IPv6 address
        assert!(matches!(
            AddressV6::from_string("invalid_address/64"),
            Err(AddressV6Error::InvalidAddress)
        ));
        assert!(matches!(
            AddressV6::from_string("abcd:efgh::/64"),
            Err(AddressV6Error::InvalidAddress)
        ));
        assert!(matches!(
            AddressV6::from_string("1:1:1:1:1::1:1/1/64"),
            Err(AddressV6Error::InvalidAddress)
        ));

        // One octet above
        assert!(matches!(
            AddressV6::from_string("1:1:1:1:1:1:1:1:1/64"),
            Err(AddressV6Error::InvalidAddress)
        ));
        // One octet short
        assert!(matches!(
            AddressV6::from_string("1:1:1:1:1:1:1/64"),
            Err(AddressV6Error::InvalidAddress)
        ));
        // Last octet overflows
        assert!(matches!(
            AddressV6::from_string("1:1:1:1:1:1:1:fffff/64"),
            Err(AddressV6Error::InvalidAddress)
        ));
        // Two double colons
        assert!(matches!(
            AddressV6::from_string("1::1:1::1:1:1/64"),
            Err(AddressV6Error::InvalidAddress)
        ));

        // Test with an invalid CIDR value
        assert!(matches!(
            AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/129"),
            Err(AddressV6Error::InvalidCidr)
        ));
        assert!(matches!(
            AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/ab"),
            Err(AddressV6Error::InvalidCidr)
        ));
        assert!(matches!(
            AddressV6::from_string("2001:0db8:85a3::8a2e:0370:7334/"),
            Err(AddressV6Error::InvalidCidr)
        ));
    }

    #[test]
    fn test_network_v6_class_display_format() {
        assert_eq!(AddressClassV6::ZERO.to_string(), "Unspecified IPv6 address");
        assert_eq!(AddressClassV6::MULTICAST.to_string(), "Multicast IPv6 address");
        assert_eq!(AddressClassV6::UNICAST.to_string(), "Unicast IPv6 address");
    }

}
