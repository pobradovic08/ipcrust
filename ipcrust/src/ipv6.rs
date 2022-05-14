use std::fmt::{Display, Formatter};


#[allow(dead_code)]
pub enum AddressFormat {
    FormatShort = 1,
    FormatCondensed = 2,
    FormatFull = 3,
}

#[derive(Copy, Clone)]
pub struct Address {
    address: u128,
}

impl Address {
    pub fn from_string(input: &str) -> Address {
        let mut ipv6_num = 0u128;
        let mut i_parts: Vec<&str> = Vec::new();

        let parts = &input.split("::").collect::<Vec<&str>>()[..];

        match parts.len() {
            // No double semicolon compression
            1 => {
                i_parts = input.split(":").collect::<Vec<&str>>();
            }
            // Double semicolon compression
            // Left and right parts
            2 => {
                let mut part_1: Vec<&str> = Vec::new();
                let mut part_2: Vec<&str> = Vec::new();

                match parts {
                    ["", b] => {
                        for _ in 0..(8 - part_2.len() - 1) {
                            part_1.push("0");
                        }
                        part_2 = b.split(":").collect::<Vec<&str>>();
                    }
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

        Address { address: ipv6_num }
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

                string = format!("{}::{}", s1.join(":"), s2.join(":"));
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

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string(AddressFormat::FormatFull))
    }
}

#[allow(dead_code)]
pub struct Network {
    ip: Address,
    mask: u128,
    cidr: u8,
}

impl Network {
    pub fn new(ip: Address, cidr: u8) -> Network {
        let mask: u128;

        match cidr {
            0 => mask = 0,
            _ => mask = u128::MAX << (128 - cidr)
        }

        Network { ip: Address { address: ip.address }, mask, cidr }
    }

    pub fn get_first_address(&self) -> Address {
        return Address { address: (self.ip.address & self.mask) };
    }

    pub fn get_last_address(&self) -> Address {
        return Address { address: self.ip.address | (!self.mask) };
    }

    pub fn print_short(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatShort), self.cidr)
    }

    pub fn print_condensed(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatCondensed), self.cidr)
    }

    pub fn print_full(&self) -> String {
        format!("{}/{}", self.get_first_address().to_string(AddressFormat::FormatFull), self.cidr)
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.print_short())
    }
}

fn print_bar_colored(cidr: u8) -> String {
    let position = cidr as usize / 4;
    let padding = position / 4;
    let bars = "▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀".chars().collect::<Vec<char>>();
    let part_1 = &bars[..(position + padding)].iter().collect::<String>();
    let part_2 = &bars[(position + padding)..].iter().collect::<String>();
    format!("\x1b[38;5;92m{}\x1b[38;5;214m{}\x1b[0m", part_1, part_2)
}

pub fn print_results(net: &Network) {
    let tw = 71;
    println!("┌{:─^1$}┐", "", tw - 2);
    println!("│{0:<1$}│", format!("\x1b[1;38;5;10m █ Address:    {}\x1b[0m", net.ip), tw + 14);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{0:<1$}│", format!(" ░ Network:    {}", net.print_short()), tw - 2);
    println!("│{0:<1$}│", format!(" ░ First IPv6: {}", net.get_first_address()), tw - 2);
    println!("│{0:<1$}│", format!(" ░ Last IPv6:  {}", net.get_last_address()), tw - 2);
    println!("│{:^1$}│", "", tw - 2);
    if net.ip.is_eui64() {
        println!("│{:<1$}│", "\x1b[1m ░ Address might be autoassigned:\x1b[0m", tw + 6);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-64:     {}", net.ip.get_eui64_string()), tw - 2);
        println!("│\x1b[0;38;5;38m{0:<1$}\x1b[0m│", format!(" ░ EUI-48:     {}", net.ip.get_eui48_string()), tw - 2);
        println!("├{:─^1$}┤", "", tw - 2);
    }

    // for note in AddressClassV6::get_additional_info(net.ip) {
    //     println!("│{:<1$}│", format!("\x1b[38;5;198m ░ Note: {}.\x1b[0m", note), tw + 13);
    // }

    println!("│{:<1$}│", "\x1b[38;5;92m ■ Network part \x1b[38;5;214m ■ Hosts part \x1b[0m", tw + 23);
    println!("│{:^1$}│", "", tw - 2);
    println!("│{:^1$}│", "\x1b[38;5;38mSubnet ID\x1b[0m", tw + 12);
    println!("│{:^1$}│", "\x1b[38;5;198m Routing prefix  \x1b[38;5;38m│  \x1b[38;5;214m Interface identifier\x1b[0m", tw + 34);
    println!("│{:^1$}│", "\x1b[38;5;198m ┌────────────┐ \x1b[38;5;38m┌┴─┐ \x1b[38;5;214m┌─────────────────┐\x1b[0m", tw + 34);
    println!("│{0:^1$}│", format!("\x1b[1m{}\x1b[0m", net.ip), tw + 6);
    println!("│{:^1$}│", print_bar_colored(net.cidr), tw + 23);
    println!("│{:^1$}│", "", tw - 2);
    println!("└{:─^1$}┘", "", tw - 2);
}
