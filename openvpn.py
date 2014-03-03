#!/usr/bin/env python
# coding=utf-8

"""Volatility plugin to extract OpenVPN credentials cached in memory."""

import struct
import volatility.plugins.common as common
import volatility.obj as obj
import volatility.utils as utils
import volatility.win32.tasks as tasks

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2014, Philip Huppert"
__license__ = "MIT"


class OpenVPN(common.AbstractWindowsCommand):
    """Extract OpenVPN credentials (username, password) cached in memory.

    This extractor currently only supports OpenVPN 2.2.2 on Windows,
    but it should be easy to adapt to other targets. Credentials are available
    in memory if the client authenticated with a username & password or entered
    a password to unlock a private key. The --auth-nocache flag must not be set.
    """

    def calculate(self):
        """Search memory for credentials"""

        kernel_memory = utils.load_as(self._config)

        # Find all OpenVPN processes
        processes = tasks.pslist(kernel_memory)
        processes = filter(
            lambda p: str(p.ImageFileName).lower() == "openvpn.exe", processes)

        # Search for credentials in each process
        for process in processes:
            process_memory = process.get_process_address_space()

            # Get some basic process information
            pid = int(process.UniqueProcessId)
            image_base = process.Peb.ImageBaseAddress
            dos_header = obj.Object(
                "_IMAGE_DOS_HEADER", offset=image_base, vm=process_memory)
            nt_header = dos_header.get_nt_header()

            # Find the .data section
            sections = nt_header.get_sections(True)
            sections = filter(lambda s: str(s.Name) == ".data", sections)
            if len(sections) != 1:
                # Section may be unavailable
                continue

            # Determine dimensions of section
            data_section = sections[0]
            data_start = data_section.VirtualAddress + image_base
            data_end = data_start + data_section.Misc.VirtualSize

            # Search static user_pass struct
            # Assumptions:
            #  - Struct is aligned on 16-byte boundary
            #  - Bool fields are 4 bytes long
            #  - Username and password buffers are 4096 bytes long
            for creds_start in xrange(data_start, data_end, 16):
                creds = process_memory.read(creds_start, 9)
                if not creds:
                    continue

                # Try to unpack and verify the beginning of the struct
                defined, nocache, username = struct.unpack("IIc", creds)
                if defined > 1 or nocache > 1 or username == "\0":
                    continue

                # Completely unpack the struct
                creds = process_memory.zread(creds_start, 4+4+4096+4096)
                defined, nocache, username, password = \
                    struct.unpack("II4096s4096s", creds)

                # Truncate string padding
                username, _, _ = username.partition("\0")
                password = password.rstrip("\0")

                # CENSOR PASSWORD
                #password = "*" * len(password)

                yield (pid, username, password)

                # Stop searching in current process
                break

    def render_text(self, outfd, data):
        """Display credentials."""

        self.table_header(outfd, [
            ("Pid", "8"),
            ("Username", "32"),
            ("Password", "32")])

        for (pid, username, password) in data:
            self.table_row(outfd, pid, username, password)
