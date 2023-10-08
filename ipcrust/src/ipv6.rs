use std::fmt::{Display, Formatter};


#[allow(dead_code)]
pub enum AddressFormat {
    FormatShort = 1,
    FormatCondensed = 2,
    FormatFull = 3,
}

#[derive(Copy, Clone)]
pub struct AddressV6 {
    address: u128,
    class: AddressClassV6
}

impl AddressV6 {
    pub fn from_string(input: &str) -> AddressV6 {
        let mut ipv6_num = 0u128;
        let mut i_parts: Vec<&str> = Vec::new();

        let parts = &input.split("::").collect::<Vec<&str>>()[..];

        match parts.len() {
            // No double colon compression
            1 => {
                i_parts = input.split(":").collect::<Vec<&str>>();
            }
            // Double colon compression
            // Left and right parts
            2 => {
                let mut part_1: Vec<&str> = Vec::new();
                let mut part_2: Vec<&str> = Vec::new();

                match parts {
                    // Zero address (::)
                    ["", ""] => {
                        return AddressV6 { address: 0, class: AddressClassV6::ZERO };
                    }
                    // Double colon in front
                    ["", b] => {
                        for _ in 0..(8 - part_2.len() - 1) {
                            part_1.push("0");
                        }
                        part_2 = b.split(":").collect::<Vec<&str>>();
                    }
                    // Double colon in the end
                    [a, ""] => {
                        part_1 = a.split(":").collect::<Vec<&str>>();
                        for _ in 0..(8 - part_1.len()) {
                            part_2.push("0");
                        }
                    }
                    _ => {
                        part_1 = parts[0].split(":").collect::<Vec<&str>>();
                        part_2 = parts[1].split(":").collect::<Vec<&str>>();
                        for _ in 0..(8 - (part_1.len() + part_2.len())) {
                            part_1.push("0");
                        }
                    }
                }

                i_parts.append(&mut part_1);
                i_parts.append(&mut part_2);
            }

            _ => panic!("Invalid IPv6 address format")
        }

        let ipv6_parts = i_parts.iter().map(
            |x| u32::from_str_radix(x, 16).unwrap()
        ).collect::<Vec<u32>>();

        if ipv6_parts.len() == 8 {
            for i in 1..=8 {
                ipv6_num += (ipv6_parts[i - 1] as u128) << 128 - (i * 16);
            }
        }

        AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) }
    }

    pub fn to_string(&self, format: AddressFormat) -> String {
        let mut hex_parts: [u32; 8] = [0; 8];
        let string: String;

        for i in 1..=8 {
            hex_parts[i - 1] = (self.address >> (128 - i * 16) & 0xffff) as u32;
        }

        match format {
            AddressFormat::FormatShort => {
                let mut p: (usize, usize) = (0, 0);
                let mut p_tmp: (usize, usize) = (0, 0);

                for i in 0..8 {
                    if hex_parts[i] == 0 {
                        p_tmp.0 = i;
                        p_tmp.1 += 1;
                    } else {
                        if p_tmp.1 > p.1 {
                            p = p_tmp;
                            p_tmp.1 = 0;
                            p_tmp.0 = 0;
                        }
                    }
                }

                if p_tmp.1 > p.1 {
                    p = p_tmp;
                }

                let start = 1 + p.0 - p.1;
                let end = p.0 + 1;

                let p1 = &hex_parts[0..start];
                let p2 = &hex_parts[end..];

                let s1 = p1.iter().map(|h| format!("{:x}", h)).collect::<Vec<String>>();
                let s2 = p2.iter().map(|h| format!("{:x}", h)).collect::<Vec<String>>();

                // If there are 8 parts use colon instead of double colon
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

        format!("{}", string)
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

#[allow(dead_code)]
pub struct NetworkV6 {
    ip: AddressV6,
    mask: u128,
    cidr: u8,
}

impl NetworkV6 {
    pub fn new(ip: AddressV6, cidr: u8) -> NetworkV6 {
        let mask: u128;

        match cidr {
            0 => mask = 0,
            _ => mask = u128::MAX << (128 - cidr)
        }

        NetworkV6 {
            ip: AddressV6 { address: ip.address, class: AddressClassV6::get(ip.address) },
            mask,
            cidr
        }
    }

    pub fn get_first_address(&self) -> AddressV6 {
        let ipv6_num: u128 = self.ip.address & self.mask;
        return AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) };
    }

    pub fn get_last_address(&self) -> AddressV6 {
        let ipv6_num: u128 = self.ip.address | (!self.mask);
        return AddressV6 { address: ipv6_num, class: AddressClassV6::get(ipv6_num) };
    }

    #[allow(dead_code)]
    pub fn contains(&self, ip: AddressV6) -> bool {
        return self.ip.address <= ip.address && ip.address <= self.get_last_address().address;
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
        let n = |network: &str, cidr: u8| NetworkV6::new(AddressV6::from_string(network), cidr);
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
    println!("│{0:<1$}│", format!(" ░ Type:       {}", net.ip.class), tw - 2);
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
    fn test_ipv6_class(){

        let n = | address: &str | AddressClassV6::get(AddressV6::from_string(address).address);

        assert_eq!(n("::"), AddressClassV6::ZERO);
        assert_eq!(n("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AddressClassV6::UNICAST);
        assert_eq!(n("ff00:0000:0000:0000:0000:0000:0000:0000"), AddressClassV6::MULTICAST);
        assert_eq!(n("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AddressClassV6::MULTICAST);
    }
}