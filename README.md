# OpenVPN credentials extractor

This repository contains a plugin for [Volatility](https://code.google.com/p/volatility/) that can extract credentials from the memory of an [OpenVPN](http://openvpn.net/index.php/open-source/) process. The username and password entered by the user, as well as passwords entered to unlock a private key can be recovered. The `--auth-nocache` flag must not be set. Currently only OpenVPN 2.2.2 on Windows is supported.

This repository also contains a small plugin to extract base64/PEM encoded RSA private keys from memory.

### Installation

Either place the plugins into Volatility's `plugins/` directory, or use the `--plugins=` option to tell Volatility where to look for plugins.

### Usage

The plugins expect no further arguments, just load a memory image and specify a profile for Volatility:

    ./vol.py -f memory_dump.elf --profile=WinXPSP3x86 openvpn
