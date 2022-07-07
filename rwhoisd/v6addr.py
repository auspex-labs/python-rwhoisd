# This file is part of python-rwhoisd
#
# Copyright (C) 2008 David E. Blacka
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import socket
import re
import struct

# a simplified regex that just makes sure that the IPv6 address string
# isn't obviously invalid.
v6char_re = re.compile(r'^[0-9a-f:]+(:(\d{1,3}\.){3}\d{1,3})?$', re.I)


def v6str_to_addr(addrstr):
    """Convert IPv6 addresses into its packed numerical value."""

    # first make sure the address is made of valid IPv6 address
    # characters.
    if not v6char_re.match(addrstr):
        raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))

    toks = addrstr.split(":")
    blanks = toks.count('')

    # convert our IPv4 section.
    if '.' in toks[-1]:
        packed_v4 = socket.inet_aton(toks[-1])
        unpacked_v4 = ["%x" % (x) for x in struct.unpack("!HH", packed_v4)]
        toks[-1:] = unpacked_v4

    if len(toks) > 8 or blanks > 3:
        raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))

    # three blanks must be ::
    if blanks == 3:
        if addrstr != "::":
            raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))
        return '\x00' * 16

    # convert the tokens into a regular array of 8 things by inserting
    # zero strings for the elided section.

    # two blanks must be ::blah or blah::
    if blanks == 2:
        z = ['0'] * (8 - len(toks) + 2)
        if addrstr.startswith("::"):
            toks[:2] = z
        elif addrstr.endswith("::"):
            toks[-2:] = z
        else:
            raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))
    # one blank is the blah::blah
    elif blanks == 1:
        z = ['0'] * (8 - len(toks) + 1)
        i = toks.index('')
        toks[i:i + 1] = z

    if len(toks) != 8:
        raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))

    toks = [int(t, 16) for t in toks]
    for t in toks:
        if t & 0xFFFF != t:
            raise socket.error("Invalid IPv6 address: '%s'" % (addrstr))
    return struct.pack("!8H", *toks)


def v6addr_to_str(addr):
    """Convert a packed numerical IPv6 address into a string.  This
    routine doesn't (yet) create an elided section."""

    if len(addr) != 16:
        raise socket.error("incorrect address length: %s (should be 16)" %
                           (len(addr)))
    nums = [x for x in struct.unpack("!8H", addr)]

    # elding support mostly cobbled from the glibc version of
    # inet_ntop

    # look for the longest string of zeros.
    cur_base = best_base = cur_len = best_len = -1

    for i in range(8):
        if nums[i] == 0:
            if cur_base == -1:
                cur_base, cur_len = i, 1
            else:
                cur_len += 1
        else:
            if cur_base != -1:
                if best_base == -1 or cur_len > best_len:
                    best_base, best_len = cur_base, cur_len
                cur_base = -1

    if cur_base != -1:
        if best_base == -1 or cur_len > best_len:
            best_base, best_len = cur_base, cur_len

    # if we have a valid string of zeros, replace them with the token.
    if best_base != -1 and best_len > 1:
        nums[best_base:best_base + best_len] = [':']

    if nums[0] == ':':
        nums.insert(0, ':')
    if nums[-1] == ':':
        nums.append(':')

    def n_to_str(n):
        if n == ':':
            return ''
        return "%x" % (n)

    strs = [n_to_str(x) for x in nums]
    return ":".join(strs)


def inet_pton(af, ip):
    if af == socket.AF_INET:
        return socket.inet_aton(ip)
    if af == socket.AF_INET6:
        return v6str_to_addr(ip)
    raise socket.error("Address family not supported by protocol")


def inet_ntop(af, packed_ip):
    if af == socket.AF_INET:
        return socket.inet.ntoa(packed_ip)
    if af == socket.AF_INET6:
        return v6addr_to_str(packed_ip)
    raise socket.error("Address family not supported by protocol")


try:
    socket.inet_pton(socket.AF_INET6, "::1")
except (AttributeError, NameError, socket.error):
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop
    socket.AF_INET6 = 'AF_INET6'

# test driver
if __name__ == "__main__":

    def try_good_addr(addr):
        try:
            a = v6str_to_addr(addr)
            b = v6addr_to_str(a)
        except socket.error as e:
            print "addr was invalid!:", e
        else:
            print "%s => %s" % (addr, b)

    try_good_addr("::")
    try_good_addr("::7")
    try_good_addr("f::")
    try_good_addr("ab:0:0:c:0:0:0:d")
    try_good_addr("ab:0:0:0:c:0:0:d")
    try_good_addr("1:2:3:4:5:6:7:8")
    try_good_addr("1:2:3::7:8")
    try_good_addr("2001:3c09:102::23:af")
    try_good_addr("::ffff:1.2.3.4")
    try_good_addr("1:2:3:4:5:6:4.3.2.1")

    def try_bad_addr(addr):
        try:
            a = v6str_to_addr(addr)
        except socket.error as e:
            print e
        else:
            print "addr was valid! %s => %s" % (addr, v6addr_to_str(a))

    # things that shouldn't parse
    try_bad_addr(":")
    try_bad_addr(":::")
    try_bad_addr("1::2::3")
    try_bad_addr("::3::")
    try_bad_addr("::1.2.3")
    try_bad_addr("12345::1")
    try_bad_addr("1:2:3:4:5:6:7:4.3.2.1")
