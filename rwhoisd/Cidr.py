# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
#
# $Id: Cidr.py,v 1.3 2003/04/28 16:43:19 davidb Exp $
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

import socket, types, copy, bisect, re

class Cidr:
    """A class representing a CIDRized IPv4 network value.

    Specifically, it is representing contiguous IPv4 network blocks
    that can be expressed as a ip-address/network-length pair."""

    # FIXME: we should probably actually make this class immutable and
    # add methods that generate copies of this class with different
    # netlens or whatever.

    ip4addr_re = re.compile("^\d{1,3}(\.\d{1,3}){0,3}(/\d{1,2})?$")
    
    def __init__(self, address, netlen = -1):
        """This takes either a formatted string in CIDR notation:
        (e.g., "127.0.0.1/32"), A tuple consisting of an formatting
        string IPv4 address and a numeric network length, or the same
        as two arguments."""

        # if we are handing a numerical address and netlen, convert
        # them directly.
        if isinstance(address, int) and netlen >= 0:
            self.netlen = netlen
            self.numaddr = address
            mask = self._mask(netlen)
            self.numaddr &= mask
            self.addr = self._convert_ip4addr(self.numaddr)
            return
        
        if not Cidr.ip4addr_re.search(address):
            raise ValueError, repr(address) + \
                  " is not a valid CIDR representation"
        
        if netlen < 0:
            if type(address) == types.StringType:
                if "/" in address:
                    self.addr, self.netlen = address.split("/", 1)
                else:
                    self.addr, self.netlen = address, 32
            elif type(address) == types.TupleType:
                self.addr, self.netlen = address
            else:
                raise TypeError, "address must be a string or a tuple"
        else:
            self.addr = address
            self.netlen = netlen

        # convert string network lengths to integer
        if type(self.netlen) == types.StringType:
            self.netlen = int(self.netlen)

        self.calc()

    def __cmp__(self, other):
        """One CIDR network block is less than another if the start
        address is numerically less or if the block is larger.  That
        is, supernets will sort before subnets.  This ordering allows
        for an effienct search for subnets of a given network."""

        # FIXME: have to convert to longs to overcome signedness problems.
        #  There is probably a better way to do this.
        res = (self.numaddr & 0xFFFFFFFFL) - (other.numaddr & 0xFFFFFFFFL)
        if (res < 0 ): return -1
        if (res > 0): return 1
        res = self.netlen - other.netlen
        return res

    def __str__(self):
        return self.addr + "/" + str(self.netlen)

    def __repr__(self):
        return "<" + str(self) + ">"

    def calc(self):
        """This method should be called after any change to the main
        internal state: netlen or numaddr."""

        # make sure the network length is valid
        if self.netlen > 32 or self.netlen < 0:
            raise TypeError, "network length must be between 0 and 32"

        # convert the string ipv4 address to a 32bit number
        self.numaddr = self._convert_ip4str(self.addr)
        # calculate our netmask
        self.mask = self._mask(self.netlen)
        # force the cidr address into correct masked notation
        self.numaddr &= self.mask

        # convert the number back to a string to normalize the string
        self.addr = self._convert_ip4addr(self.numaddr)

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
        return self._convert_ip4addr(self.mask)
    
    def length(self):
        """return the length (in number of addresses) of this network block"""
        return netlen_to_length(self.netlen)

    def end(self):
        """return the last IP address in this network block"""
        return self._convert_ip4addr(self.numaddr + self.length() - 1)

    def to_netblock(self):
        return (self.addr, self.end())
    
    def _convert_ip4str(self, addr):
        p = 3; a = 0
        for octet in addr.split(".", 3):
            o = int(octet);
            if (o & 0xFF != o):
                raise SyntaxWarning, "octet " + str(o) + " isn't in range"
            a |= o << (p * 8)
            p -= 1
        return a

    def _convert_ip4addr(self, numaddr):
        res = str((numaddr & 0xFF000000) >> 24 & 0xFF) + "." + \
              str((numaddr & 0x00FF0000) >> 16) + "." + \
              str((numaddr & 0x0000FF00) >> 8) + "." + \
              str(numaddr & 0x000000FF)
        return res

    def _mask(self, len):
        return 0xFFFFFFFF << (32 - len)

    def clone(self):
        # we can get away with a shallow copy (so far)
        return copy.copy(self)


def valid_cidr(address):
    """Returns the converted Cidr object  if 'address' is valid
    CIDR notation, False if not.  For the purposes of this module,
    valid CIDR notation consists of 1 to 4 octets separated by '.'
    characters, with an optional trailing "/netlen"."""

    if isinstance(address, Cidr): return address
    try:
        c = Cidr(address)
        return c
    except:
        return False


def netlen_to_length(netlen):
    """Convert a network-length to the length of the block in ip
    addresses."""

    return 1 << (32 - netlen);

def netblock_to_cidr(start, end):
    """Convert an arbitrary network block expressed as a start and end
    address (inclusive) into a series of valid CIDR blocks."""

    def largest_prefix(length):
        # calculates the largest network length (smallest mask length)
        # that can fit within the block length.
        i = 1; v = length
        while i <= 32:
            if v & 0x80000000: break
            i += 1; v <<= 1
        return i
    def netlen_to_mask(n):
        # convert the network length into its netmask
        return ~((1 << (32 - n)) - 1)
    

    # convert the start and ending addresses of the netblock to Cidr
    # object, mostly so we can get the numeric versions of their
    # addresses.
    cs = valid_cidr(start)
    ce = valid_cidr(end)

    # if either the start or ending addresses aren't valid ipv4
    # address, quit now.
    if not cs or not ce:
        return None

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
        cv = Cidr(s, netlen)
        res.append(Cidr(s, netlen))
        # and setup for the next round:
        cur_len = netlen_to_length(netlen)
        s         += cur_len
        block_len -= cur_len
        netlen = largest_prefix(block_len + 1)
    return res

# test driver
if __name__ == "__main__":
    a = Cidr("127.00.000.1/24")
    b = Cidr("127.0.0.1", 32)
    c = Cidr("24.232.119.192", 26)
    d = Cidr("24.232.119.0", 24)
    e = Cidr("24.224.0.0", 11)
    f = Cidr("216.168.111.0/27");
    g = Cidr("127.0.0.2/31");
    h = Cidr("127.0.0.16/32")
    print f.addr
    
    try:
        bad = Cidr("24.261.119.0", 32)
    except Warning, x:
        print "warning:", x
    
    print "cidr:", a, "num addresses:", a.length(), "ending address", \
          a.end(), "netmask", a.netmask()
    
    clist = [a, b, c, d, e, f, g, h]
    print "unsorted list of cidr objects:\n  ", clist

    clist.sort()
    print "sorted list of cidr object:\n  ", clist

    netblocks = [ ("192.168.10.0", "192.168.10.255"),
                  ("192.168.10.0", "192.168.10.63"),
                  ("172.16.0.0", "172.16.127.255"),
                  ("24.33.41.22", "24.33.41.37"),
                  ("196.11.1.0", "196.11.30.255"),
                  ("192.247.1.0", "192.247.10.255")]
                  
    for start, end in netblocks:
        print "netblock %s - %s:" % (start, end)
        blocks = netblock_to_cidr(start, end)
        print blocks
