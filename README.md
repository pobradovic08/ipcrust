# ipcrust

[![Crates.io](https://img.shields.io/crates/v/ipcrust)](https://crates.io/crates/ipcrust)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

IP network calculator written in Rust. Supports both IPv4 and IPv6 addresses.

## Features

- IPv4 subnet calculation (network, broadcast, first/last usable address, usable hosts)
- IPv4 address class detection (A, B, C, D, E)
- IPv4 CIDR and dotted-decimal mask support
- IPv6 prefix calculation (first/last address, containment checks)
- IPv6 short, condensed, and full address formatting (RFC 5952 compliant)
- IPv6 EUI-64/EUI-48 (MAC address) detection and extraction
- Colored terminal output with binary and bar representations

## Installation

### From crates.io

```sh
cargo install ipcrust
```

### From source

```sh
git clone https://github.com/pobradovic08/ipcrust.git
cd ipcrust
cargo build --release
```

## Usage

```
ipcrust <ip>/<cidr>
ipcrust <ipv4>/<mask>
ipcrust <ipv4> <mask>
ipcrust <ip>
```

### Examples

```sh
# IPv4 with CIDR notation
ipcrust 192.168.1.10/24

# IPv4 with dotted-decimal mask
ipcrust 10.0.0.1/255.255.255.0

# IPv4 with mask as separate argument
ipcrust 10.0.0.1 255.255.255.0

# IPv6
ipcrust 2001:db8:85a3::8a2e:370:7334/64

# Host address (no mask)
ipcrust 192.168.1.1
```

## License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0).
