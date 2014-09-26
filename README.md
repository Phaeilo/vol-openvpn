# OpenVPN credentials extractor

This repository contains a plugin for [Volatility](https://code.google.com/p/volatility/) that can extract credentials
from the memory of an [OpenVPN](http://openvpn.net/index.php/open-source/) process. The username and password entered
by the user, as well as passwords entered to unlock a private key can be recovered. OpenVPN's `--auth-nocache` flag
must not be set. The plugin supports OpenVPN 2.X.X on Windows. It was successfully tested with OpenVPN 2.2.2, 2.3.2 and
2.3.4 on Windows XP (x86) and Windows 7 (x86 & x64).

This repository also contains a small plugin to extract base64/PEM encoded RSA private keys from memory.

### Motivation

This plugin was developed as a part of a university assignment about virtual machine introspection. The Volatility
framework was chosen, because it offers a wide variety of plugins and can interface with hypervisors through
[libvmi](https://code.google.com/p/vmitools/) to perform introspection. OpenVPN was chosen as a target, because it is
widely deployed at the university to facilitate network access control. This allowed to evaluate the security of the
OpenVPN deployment and demonstrate the plugin on an application that students are familiar with in everyday use.

In a real-world scenario, the plugin may be handy to extract credentials during an investigation or pentest engagement.
You can also use it to validate that OpenVPN's `--auth-nocache` flag works as intended.

### Installation

Either place the plugins into Volatility's `plugins/` directory, or use the `--plugins=` option to point Volatility
to the directory containing `openvpn.py`.

### Usage

The plugins expect no further arguments, just load a memory image and specify a profile for Volatility.
A memory sample can be downloaded from https://mega.co.nz/#!Wx5kiZZS!77NiMTl8B_imwhl4JSg0lmRm90LZ9wgvFhQYxmmOioo.
After downloading the memory dump, decompress it and run Volatility to extract the credentials:

    unxz "OpenVPN-2.3.4 XP 32.elf.xz"
    volatility -f "OpenVPN-2.3.4 XP 32.elf" --profile=WinXPSP3x86 openvpn
