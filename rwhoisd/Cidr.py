# This file is part of python-rwhoisd
#
# Copyright (C) 2003, 2008 David E. Blacka
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

import socket, types, copy, bisect, struct

class Cidr:
    """A class representing a generic CIDRized network value."""    

    @staticmethod
    def create(address, netlen = -1):
        """Construct either a CidrV4 or CidrV6 object."""
        if isinstance(address, int):
            return CidrV4(address, netlen)
        if isinstance(address, long):
            if address <= pow(2, 32):
                return CidrV4(address, netlen)
            return CidrV6(address, netlen)
        if ":" in address:
            return CidrV6(address, netlen)
        return CidrV4(address, netlen)


    def _initialize(self, address, netlen):
        """This a common constructor that is used by the subclasses."""

        if isinstance(address, int) or \
                isinstance(address, long) and netlen >= 0:
            self.numaddr, self.netlen = address, netlen
            self.addr = self._convert_ipaddr(address)
            self.calc()
            return

        if not self.is_valid_cidr(address):
            raise ValueError, \
                repr(address) + " is not a valid CIDR representation"

        if netlen < 0:
            if type(address) == types.StringType:
                if "/" in address:
                    self.addr, self.netlen = address.split("/", 1)
                else:
                    self.addr, self.netlen = address, self._max_netlen()
            elif type(address) == types.TupleType:
                self.addr, self.netlen = address
            else:
                raise TypeError, "address must be a string or a tuple"
        else:
            self.addr, self.netlen = address, netlen


        # convert string network lengths to integer
        if type(self.netlen) == types.StringType:
            self.netlen = int(self.netlen)

        self.calc()

    def __str__(self):
        return self.addr + "/" + str(self.netlen)

    def __repr__(self):
        return "<" + str(self) + ">"

    def __cmp__(self, other):
        """One CIDR network block is less than another if the start
        address is numerically less or if the block is larger.  That
        is, supernets will sort before subnets.  This ordering allows
        for an efficient search for subnets of a given network."""

        res = self._base_mask(self.numaddr) - other._base_mask(other.numaddr)
        if res == 0: res = self.netlen - other.netlen
        if res < 0: return -1
        if res > 0: return 1
        return 0

    def calc(self):
        """This method should be called after any change to the main
        internal state: netlen or numaddr."""

        # make sure the network length is valid
        if not self.is_valid_netlen(self.netlen):
            raise TypeError, "network length must be between 0 and %d" % \
                (self._max_netlen())

        # convert the string ipv4 address to a 32bit number
        self.numaddr = self._convert_ipstr(self.addr)
        # calculate our netmask
        self.mask = self._mask(self.netlen)
        # force the cidr address into correct masked notation
        self.numaddr &= self.mask

        # convert the number back to a string to normalize the string
        self.addr = self._convert_ipaddr(self.numaddr)

    def is_supernet(self, other):
        """returns True if the other Cidr object is a supernet (an
        enclosing network block) of this one.  A Cidr object is a
        supernet of itself."""
        return other.numaddr & self.mask == self.numaddr

    def is_subnet(self, other):
        """returns True if the other Cidr object is a subnet (an
        enclosednetwork block) of this one.  A Cidr object is a
        subnet of itself."""
        return self.numaddr & other.mask == other.numaddr

    def netmask(self):
        """return the netmask of this Cidr network"""
        return self._convert_ipaddr(self.mask)
    
    def length(self):
        """return the length (in number of addresses) of this network block"""
        return 1 << (self._max_netlen() - self.netlen);

    def end(self):
        """return the last IP address in this network block"""
        return self._convert_ipaddr(self.numaddr + self.length() - 1)

    def to_netblock(self):
        return (self.addr, self.end())

    def clone(self):
        # we can get away with a shallow copy (so far)
        return copy.copy(self)
    
    def is_ipv6(self):
        if isinstance(self, CidrV6): return True
        return False

    def is_valid_cidr(self, address):
        if "/" in address:
            addr, netlen = address.split("/", 1)
            netlen = int(netlen)
        else:
            addr, netlen = address, 0
        return self._is_valid_address(addr) and self.is_valid_netlen(netlen)

    def is_valid_netlen(self, netlen):
        if netlen < 0: return False
        if netlen > self._max_netlen(): return False
        return True


class CidrV4(Cidr):
    """A class representing a CIDRized IPv4 network value.

    Specifically, it is representing a contiguous IPv4 network block
    that can be expressed as a ip-address/network-length pair."""

    def __init__(self, address, netlen = -1):
        """This takes either a formatted string in CIDR notation:
        (e.g., "127.0.0.1/32"), A tuple consisting of an formatting
        string IPv4 address and a numeric network length, or the same
        as two arguments."""
        
        self._initialize(address, netlen)
        
    def _is_valid_address(self, address):
        """Returns True if the address is a legal IPv4 address."""
        try:
            self._convert_ipstr(address)
            return True
        except socket.error:
            return False

    def _base_mask(self, numaddr):
        return numaddr & 0xFFFFFFFFL

    def _max_netlen(self):
        return 32

    def _convert_ipstr(self, addr):
        packed_numaddr = socket.inet_aton(addr)
        return struct.unpack("!I", packed_numaddr)[0]

    def _convert_ipaddr(self, numaddr):
        packed_numaddr = struct.pack("!I", numaddr)
        return socket.inet_ntoa(packed_numaddr)

    def _mask(self, len):
        return self._base_mask(0xFFFFFFFF << (32 - len))
        

class CidrV6(Cidr):
    """A class representing a CIDRized IPv6 network value.

    Specifically, it is representing a contiguous IPv6 network block
    that can be expressed as a ipv6-address/network-length pair."""
    
    ip6_base_mask  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL # 128-bits of all ones.
    ip6_lower_mask = 0x0000000000000000FFFFFFFFFFFFFFFFL
    ip6_upper_mask = 0xFFFFFFFFFFFFFFFF0000000000000000L

    def __init__(self, address, netlen = -1):
        
        self._initialize(address, netlen)

    def _is_valid_address(self, address):
        try:
            self._convert_ipstr(address)
            return True
        except socket.error, e:
            print "Failed to convert address string '%s': " + str(e) % (address)
            return False

    def _base_mask(self, numaddr):
        return numaddr & CidrV6.ip6_base_mask

    def _max_netlen(self):
        return 128

    def _convert_ipstr(self, addr):
        packed_numaddr = socket.inet_pton(socket.AF_INET6, addr)
        upper, lower = struct.unpack("!QQ", packed_numaddr);
        return (upper << 64) | lower
    
    def _convert_ipaddr(self, numaddr):
        upper = (numaddr & CidrV6.ip6_upper_mask) >> 64;
        lower = numaddr & CidrV6.ip6_lower_mask;
        packed_numaddr = struct.pack("!QQ", upper, lower)
        return socket.inet_ntop(socket.AF_INET6, packed_numaddr)

    def _mask(self, len):
        return self._base_mask(CidrV6.ip6_base_mask << (128 - len))


def valid_cidr(address):
    """Returns the converted Cidr object if 'address' is valid CIDR
    notation, False if not.  For the purposes of this module, valid
    CIDR notation consists of a IPv4 or IPv6 address with an optional
    trailing "/netlen"."""

    if isinstance(address, Cidr): return address
    try:
        c = Cidr.create(address)
        return c
    except (ValueError, socket.error):
        return False

def netblock_to_cidr(start, end):
    """Convert an arbitrary network block expressed as a start and end
    address (inclusive) into a series of valid CIDR blocks."""

    def largest_prefix_v4(length):
        # calculates the largest network length (smallest mask length)
        # that can fit within the block length.
        i = 1; v = length
        while i <= 32:
            if v & 0x80000000: break
            i += 1; v <<= 1
        return i
    def largest_prefix_v6(length):
        i = 1; v = length
        while i <= 128:
            if v & 0x80000000000000000000000000000000L: break
            i += 1; v <<= 1
        return i
    def netlen_to_mask_v4(n):
        # convert the network length into its netmask
        return ~((1 << (32 - n)) - 1)
    def netlen_to_mask_v6(n):
        return ~((1 << (128 -n)) - 1)

    # convert the start and ending addresses of the netblock to Cidr
    # object, mostly so we can get the numeric versions of their
    # addresses.
    cs = valid_cidr(start)
    ce = valid_cidr(end)

    # if either the start or ending addresses aren't valid addresses,
    # quit now.
    if not cs or not ce:
        print "Invalid start or end address"
        return None
    # if the start and ending addresses aren't in the same family, quit now
    if cs.is_ipv6() != ce.is_ipv6():
        print "start and end address not same family"
        return None
    
    if cs.is_ipv6():
        largest_prefix = largest_prefix_v6
        netlen_to_mask = netlen_to_mask_v6
    else:
        largest_prefix = largest_prefix_v4
        netlen_to_mask = netlen_to_mask_v4

    # calculate the number of IP address in the netblock
    block_len = ce.numaddr - cs.numaddr
    
    # calcuate the largest CIDR block size that fits
    netlen = largest_prefix(block_len + 1)
    
    res = []; s = cs.numaddr
    while block_len > 0:
        mask = netlen_to_mask(netlen)
        # check to see if our current network length is valid
        if (s & mask) != s:
            # if not, shrink the network block size
            netlen += 1
            continue
        # otherwise, we have a valid CIDR block, so add it to the list
        cv = Cidr.create(s, netlen)
        res.append(Cidr.create(s, netlen))
        # and setup for the next round:
        cur_len = netlen_to_length(netlen)
        s         += cur_len
        block_len -= cur_len
        netlen = largest_prefix(block_len + 1)
    return res

# test driver
if __name__ == "__main__":
    import sys
    a = Cidr.create("127.00.000.1/24")
    b = Cidr.create("127.0.0.1", 32)
    c = Cidr.create("24.232.119.192", 26)
    d = Cidr.create("24.232.119.0", 24)
    e = Cidr.create("24.224.0.0", 11)
    f = Cidr.create("216.168.111.0/27");
    g = Cidr.create("127.0.0.2/31");
    h = Cidr.create("127.0.0.16/32")
    i = Cidr.create("3ffe:4:201e:beef::0/64");
    j = Cidr.create("2001:3c01::/32")

    print f.addr
    print j.addr
    
    try:
        bad = Cidr.create("24.261.119.0", 32)
    except ValueError, x:
        print "error:", x
    
    print "cidr:", a, "num addresses:", a.length(), "ending address", \
        a.end(), "netmask", a.netmask()

    print "cidr:", j, "num addresses:", j.length(), "ending address", \
        j.end(), "netmask", j.netmask()

    clist = [a, b, c, d, e, f, g, h, i , j]
    print "unsorted list of cidr objects:\n  ", clist


    clist.sort()
    print "sorted list of cidr object:\n  ", clist


    netblocks = [ ("192.168.10.0", "192.168.10.255"),
                  ("192.168.10.0", "192.168.10.63"),
                  ("172.16.0.0", "172.16.127.255"),
                  ("24.33.41.22", "24.33.41.37"),
                  ("196.11.1.0", "196.11.30.255"),
                  ("192.247.1.0", "192.247.10.255"),
                  ("3ffe:4:5::", "3ffe:4:5::ffff") ]
                  
    for start, end in netblocks:
        print "netblock %s - %s:" % (start, end)
        blocks = netblock_to_cidr(start, end)
        print blocks
