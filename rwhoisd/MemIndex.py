# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
#
# $Id: MemIndex.py,v 1.2 2003/04/28 16:43:19 davidb Exp $
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

import bisect, types
import Cidr

class MemIndex:
    """This class implements a simple in-memory key-value map.  This
    index supports efficient prefix matching (as well as pretty
    efficient exact matching).  Internally, it is implemented as a
    sorted list supporting binary searches."""

    # NOTE: This implementation is probably far from as efficient as
    # it could be.  Ideally, we should avoid the use of custom
    # comparison functions, so that list.sort() will use built-in
    # comparitors.  This would mean storing raw key tuples in index as
    # opposed to element objects.  Also, it would mean avoiding the
    # use of objects (like Cidr) as keys in favor of a primitive type.
    # In the Cidr case, we would either have to use longs or strings,
    # as Python doesn't seem to have an unsigned 32-bit integer type.
    
    def __init__(self):
        self.index = []
        self.sorted = False

    def add(self, key, value=None):
        """Add a key-value pair to the map.  If the map is already in
        the prepared state, this operation will preserve it, so don't
        use this if many elements are to be added at once.  The 'key'
        argument may be a 2 element tuple, in which case 'value' is
        ignored."""

        if isinstance(key, types.TupleType):
            el = element(key[0], key[1])
        else:
            el = element(key, value)

        if self.sorted:
            i = bisect.bisect_left(self.index, el)
            while i < len(self.index):
                if self.index[i].total_equals(el):
                    break
                if self.index[i] != el:
                    self.index.insert(i, el)
                    break
                i += 1
            else:
                self.index.append(el)
        else:
            self.index.append(el)

    def addlist(self, list):
        """Add the entire list of elements to the map.  The elements
        of 'list' may be 2 element tuples or actual 'element' objects.
        Use this method to add many elements at once."""

        self.sorted = False
        for i in list:
            if isinstance(i, types.TupleType):
                self.index.append(element(i[0], i[1]))
            elif isinstance(i, element):
                self.index.append(i)

    def prepare(self):
        """Put the map in a prepared state, if necessary."""

        n = len(self.index)
        if not n: return
        if not self.sorted:
            self.index.sort()
            # unique the index
            last = self.index[0]
            lasti = i = 1
            while i < n:
                if not self.index[i].total_equals(last):
                    self.index[lasti] = last = self.index[i]
                    lasti += 1
                i += 1
            self.index[lasti:]
            self.sorted = True

    def _find(self, key):
        """Return the (search_element, index) tuple.  Used internally
        only."""
        
        self.prepare()
        search_el = element(key, None)
        i = bisect.bisect_left(self.index, search_el)
        if i > len(self.index) or i < 0:
            print "warning: bisect.bisect_left returned something " + \
                  "unexpected:", i, len(self.index)
        return (search_el, i)

    def find(self, key, prefix_match=False, max=0):
        """Return a list of values whose keys string match 'key'.  If
        prefix_match is True, then keys will match if 'key' is a
        prefix of the element key."""

        search_el, i = self._find(key)
        res = []
        while i < len(self.index):
            if max and len(res) == max: break
            if search_el.equals(self.index[i], prefix_match):
                res.append(self.index[i].value)
                i += 1
            else:
                break
        return res

class CidrMemIndex(MemIndex):
    """This is an in-memory map that has been extended to support CIDR
    searching semantics."""

    # NOTE: this structure lends to fairly efficient exact searches
    # (O[log2N]), effience subnet searches (also O[log2N]), but not
    # terribly efficient supernet searches (O[32log2N]), because we
    # have to potentially do 32 exact matches.  If we want efficient
    # supernet searches, we will probably have to use some sort of
    # general (i.e., not binary) search tree datastructure, as there
    # is no sorted ordering that will efficiently give supernets that
    # I can think of.

    def add(self, key, value=None):
        if isinstance(key, types.TupleType):
            MemIndex.add(self, (Cidr.valid_cidr(key[0]), key[1]), value)
        else:
            MemIndex.add(self, Cidr.valid_cidr(key), value)
        return

    def addlist(self, list):

        # make sure the keys are Cidr objects
        for i in list:
            if isinstance(i, types.TupleType):
                i = (Cidr.valid_cidr(el[0]), el[1])
            elif isinstance(el, element):
                i.key = Cidr.valid_cidr(i.key)
        
        MemIndex.addlist(self, list)
        return
    
    def find_exact(self, key, max = 0):

        key = Cidr.valid_cidr(key)
        search_el, i = self._find(key)
        res = []
        while i < len(self.index) and self.index[i].key == key:
            res.append(self.index[i].value)
            if max and len(res) == max: break
            i += 1
        return res
    
    def find_subnets(self, key, max = 0):
        """Return all values that are subnets of 'key', including any
        that match 'key' itself."""

        key = Cidr.valid_cidr(key)
        search_el, i = self._find(key)

        res = []
        while i < len(self.index) and self.index[i].key.is_subnet(key):
            if max and len(res) == max: break
            res.append(self.index[i].value)
            i += 1
        return res

    def find_supernets(self, key, max = 0):
        """Return all values that are supernets of 'key', including
        any that match 'key' itself."""

        key = Cidr.valid_cidr(key)
        k = key.clone()
        res = []
        while k.netlen >= 0:
            k.calc()
            res += self.find_exact(k, max)
            if max and len(res) >= max:
                return res[:max]
            k.netlen -= 1

        
        return res

    def find(self, key, prefix_match=0, max=0):
        """Return either the exact match of 'key', or the closest
        supernet of 'key'.  If prefix_match is True, then find all
        supernets of 'key'"""

        key = Cidr.valid_cidr(key)
        if prefix_match == 0:
            res = self.find_exact(key, max)
                
            if not res:
                # now do a modified supernet search that stops after
                # the first proper supernet, but gets all values
                # matching that supernet key
                k = key.clone()
                k.netlen -= 1
                while not res and k.netlen >= 0:
                    k.calc()
                    res = self.find_exact(k, max)
                    k.netlen -= 1
            return res
        
        # for now, a prefix match means all supernets
        return self.find_supernets(key, max)

class ComboMemIndex:
    """This is an in-memory map that contains both a normal string
    index and a CIDR index.  Valid CIDR values we be applied against
    the CIDR index.  Other values will be applied against the normal
    index."""
    
    def __init__(self):
        self.normal_index = MemIndex()
        self.cidr_index   = CidrMemIndex()

    def add(self, key, value = None):
        """Add a key,value pair to the correct map.  See MemIndex for
        the behavior of this method"""
        
        if isinstance(key, types.TupleType):
            k = key[0]
        else:
            k = key
        c = Cidr.valid_cidr(key)
        if c:
            self.cidr_index.add(key, value)
        else:
            self.normal_index.add(key, value)
        return

    def addlist(self, list):
        """Add a list of elements or key, value tuples to the
        appropriate maps."""
        
        cidr_list = []
        normal_list = []
        
        for i in list:
            if isinstance(i, element):
                k, v = i.key, i.value
            elif isinstance(i, types.TupleType):
                k, v = i[:2]
            
            c = Cidr.valid_cidr(k)
            if c:
                cidr_list.append((c, v))
            else:
                normal_list.append((k, v))

        if cidr_list:
            self.cidr_index.addlist(cidr_list)
        if normal_list:
            self.normal_index.addlist(normal_list)
        return

    def prepare(self):
        """Prepare the internally held maps for searching."""

        self.cidr_index.prepare()
        self.normal_index.prepare()

    def find(self, key, prefix_match=False, max=0):
        """Return a list of values whose keys match 'key'."""

        c = Cidr.valid_cidr(key)
        if c:
            return self.cidr_index.find(c, prefix_match, max)
        return self.normal_index.find(key, prefix_match, max)

    def find_exact(self, key, max = 0):
        """Return a list of values whose keys match 'key'.  if 'key'
        is not a CIDR value, then this is the same as find()."""

        c = Cidr.valid_cidr(key)
        if c:
            return self.cidr_index.find_exact(c, max)
        return self.normal_index.find(key, False, max)

    def find_subnets(self, key, max = 0):
        """If 'key' is a CIDR value (either a Cidr object or a valid
        CIDR string representation, do a find_subnets on the internal
        CidrMemIndex, otherwise return None."""
        
        c = Cidr.valid_cidr(key)
        if c: return self.cidr_index.find_subnets(key, max)
        return None

    def find_supernets(self, key, max = 0):
        """If 'key' is a CIDR value (either a Cidr object or a valid
        CIDR string representation, do a find_supernets on the internal
        CidrMemIndex, otherwise return None."""

        c = Cidr.valid_cidr(key)
        if c: return self.cidr_index.find_supernets(key, max)
        return None
    
class element:
    """This is the base element class.  It basically exists to
    simplify sorting."""
    
    def __init__(self, key, value):
        self.key   = key
        self.value = value

    def __cmp__(self, other):
        """Compare only on the key."""

        if not type(self.key) == type(other.key):
            print "other is incompatible type?", repr(other.key), other.key
        if self.key < other.key:
            return -1
        if self.key == other.key:
            return 0
        return 1

    def __str__(self):
        return "<" + str(self.key) + ", " + str(self.value) + ">"

    def __repr__(self):
        return "element" + str(self)
    
    def __hash__(self):
        return self.key.__hash__()

    def equals(self, other, prefix_match=0):
        if prefix_match:
            return self.key == other.key[:len(self.key)]
        return self.key == other.key

    def total_equals(self, other):
        if not isinstance(other, type(self)): return False
        return self.key == other.key and self.value == other.value

if __name__ == "__main__":

    source = [ ("foo", "foo-id"), ("bar", "bar-id"), ("baz", "baz-id"),
               ("foobar", "foo-id-2"), ("barnone", "bar-id-2"),
               ("zygnax", "z-id") ]

    mi = MemIndex()
    mi.addlist(source)

    print "finding foobar:"
    res = mi.find("foobar")
    print res

    print "finding foo*:"
    res = mi.find("foo", 1)
    print res

    print "finding baz:"
    res = mi.find("baz")
    print res

    print "adding bork"
    mi.add("bork", "bork-id")

    print "finding b*:"
    res = mi.find("b", 1)
    print res

    ci = CidrMemIndex()

    ci.add(Cidr.Cidr("127.0.0.1/24"), "net-local-1");
    ci.add(Cidr.Cidr("127.0.0.1/32"), "net-local-2");
    ci.add(Cidr.Cidr("216.168.224.0", 22), "net-vrsn-1")
    ci.add(Cidr.Cidr("216.168.252.1", 32), "net-vrsn-2")
    ci.add(Cidr.Cidr("24.36.191.0/24"), "net-foo-c")
    ci.add(Cidr.Cidr("24.36.191.32/27"), "net-foo-sub-c")
    ci.add(Cidr.Cidr("24.36/16"), "net-foo-b")

    print "finding exactly 127.0.0.0/24"
    res = ci.find(Cidr.Cidr("127.0.0.0/24"))
    print res

    print "finding exactly 127.0.0.16/32"
    res = ci.find(Cidr.Cidr("127.0.0.16/32"))
    print res

    print "finding supernets of 127.0.0.16/32"
    res = ci.find_supernets(Cidr.Cidr("127.0.0.16/32"))
    print res
    
    print "finding supernets of 24.36.191.32/27"
    res = ci.find(Cidr.Cidr("24.36.191.32/27"), 1)
    print res

    print "finding supernets of 24.36.191.33/27"
    res = ci.find_supernets(Cidr.Cidr("24.36.191.33/27"))
    print res

    print "finding supernets of 24.36.191.64/27"
    res = ci.find_supernets(Cidr.Cidr("24.36.191.64/27"))
    print res

    print "finding subnets of 127.0/16"
    res = ci.find_subnets(Cidr.Cidr("127.0/16"))
    print res
