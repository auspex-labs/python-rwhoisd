import socket, types, copy, bisect, re

class Cidr:
    """A class representing a CIDRized IPv4 network value.

    Specifically, it is representing contiguous IPv4 network blocks
    that can be expressed as a ip-address/network length pair."""

    # FIXME: we should probably actually make this class immutable and
    # add methods that generate copies of this class with different
    # netlens or whatever.

    ip4addr_re = re.compile("^\d{1,3}(\.\d{1,3}){0,3}(/\d{1,2})?$")
    
    def __init__(self, address, netlen = -1):
        """This takes either a formatted string in CIDR notation:
        (e.g., "127.0.0.1/32"), A tuple consisting of an formatting
        string IPv4 address and a numeric network length, or the same
        as two arguments."""

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
        return 1 << (32 - self.netlen);

    def end(self):
        """return the last IP address in this network block"""
        return self._convert_ip4addr(self.numaddr + self.length() - 1)
        
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


# test driver
if __name__ == "__main__":
    a = Cidr("127.00.000.1/24")
    b = Cidr("127.0.0.1", 32)
    c = Cidr("24.232.119.192", 26)
    d = Cidr("24.232.119.0", 24)
    e = Cidr(("24.224.0.0", 11))
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
