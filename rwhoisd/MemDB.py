import bisect, types
import MemIndex, Cidr
from Rwhois import rwhoisobject

class MemDB:

    def __init__(self):

        # a dictonary holding the various attribute indexes.  The keys
        # are lowercase attribute names, values are MemIndex or
        # CidrMemIndex objects.
        self.indexes = {}

        # a dictonary holding the actual rwhoisobjects.  keys are
        # string IDs, values are rwhoisobject instances.
        self.main_index = {}

        # dictonary holding all of the seen attributes.  keys are
        # lowercase attribute names, value is a character indicating
        # the index type (if indexed), or None if not indexed.  Index
        # type characters a 'N' for normal string index, 'C' for CIDR
        # index.
        self.attrs = {}

        # Lists containing attribute names that have indexes by type.
        # This exists so unconstrained searches can just iterate over
        # them.
        self.normal_indexes = []
        self.cidr_indexes = []

        # dictonary holding all of the seen class names.  keys are
        # lowercase classnames, value is always None.
        self.classes = {}

        # dictionary holding all of the seen auth-areas.  keys are
        # lowercase authority area names, value is always None.
        self.authareas = {}

    def init_schema(self, schema_file):
        """Initialize the schema from a schema file.  Currently the
        schema file is a list of 'attribute_name = index_type' pairs,
        one per line.  index_type is one of N or C, where N means a
        normal string index, and C means a CIDR index.

        It should be noted that this database implementation
        implements a global namespace for attributes, which isn't
        really correct according to RFC 2167.  RFC 2167 dictates that
        different authority area are actually autonomous and thus have
        separate schemas."""

        # initialize base schema

        self.attrs['id']         = "N"
        self.attrs['auth-area']  = None
        self.attrs['class-name'] = None
        self.attrs['updated']    = None
        self.attrs['referred-auth-area'] = "R"

        sf = open(schema_file, "r")

        for line in sf.xreadlines():
            line = line.strip()
            if not line or line.startswith("#"): continue

            attr, it = line.split("=")
            self.attrs[attr.strip().lower()] = it.strip()[0].upper()

        for attr, index_type in self.attrs.items():
            if index_type == "N":
                # normal index
                self.indexes[attr] = MemIndex.MemIndex()
                self.normal_indexes.append(attr)
            elif index_type == "A":
                # "all" index -- both a normal and a cidr index
                self.indexes[attr] = MemIndex.ComboMemIndex()
                self.normal_indexes.append(attr)
                self.cidr_indexes.append(attr)
            elif index_type == "R":
                # referral index, an all index that must be searched
                # explictly by attribute
                self.indexes[attr] = MemIndex.ComboMemIndex()
            elif index_type == "C":
                # a cidr index
                self.indexes[attr] = MemIndex.CidrMemIndex()
                self.cidr_indexes.append(attr)
        return

    def add_object(self, obj):
        """Add an rwhoisobject to the raw indexes, including the
        master index."""

        # add the object to the main index
        id = obj.getid()
        if not id: return
        id = id.lower()

        self.main_index[id] = obj

        for a,v in obj.items():
            # note the attribute.
            index_type = self.attrs.setdefault(a, None)
            v = v.lower()
            # make sure that we note the auth-area and class
            if a == 'auth-area':
                self.authareas.setdefault(v, None)
            elif a == 'class-name':
                self.classes.setdefault(v, None)

            if index_type:
                index = self.indexes[a]
                index.add(v, id)

    def load_data(self, data_file):
        """Load data from rwhoisd-style TXT files (i.e., attr:value,
        records separated with a "---" bare line)."""

        df = open(data_file, "r")
        obj = rwhoisobject()

        for line in df.xreadlines():
            line = line.strip()
            if line.startswith("#"): continue
            if not line or line.startswith("---"):
                # we've reached the end of an object, so index it.
                self.add_object(obj)
                # reset obj
                obj = rwhoisobject()
                continue

            a, v = line.split(":", 1)
            obj.add_attr(a, v.lstrip())

        self.add_object(obj)
        return

    def index_data(self):
        """Prepare the indexes for searching.  Currently, this isn't
        strictly necessary (the indexes will prepare themselves when
        necessary), but it should elminate a penalty on initial
        searches"""

        for i in self.indexes.values():
            i.prepare()
        return

    def is_attribute(self, attr):
        return self.attrs.has_key(attr.lower())

    def is_indexed_attr(self, attr):
        if self.is_attribute(attr):
            return self.attrs[attr.lower()]
        return False

    def is_objectclass(self, objectclass):
        return self.classes.has_key(objectclass.lower())

    def is_autharea(self, aa):
        return self.authareas.has_key(aa.lower())

    def fetch_objects(self, id_list):
        return [ self.main_index[x] for x in id_list
                 if self.main_index.has_key(x) ]

    def search_attr(self, attr, value, max = 0):

        """Search for a value in a particular attribute's index.  If
        the attribute is cidr indexed, an attempt to convert value
        into a Cidr object will be made.  Returns a list of object ids
        (or an empty list if nothing was found)"""

        attr = attr.lower()
        index_type = self.attrs.get(attr)
        index = self.indexes.get(attr)
        if not index: return []

        super_prefix_match = False
        if value.endswith("**"):
            super_prefix_match = True

        prefix_match = False
        if value.endswith("*"):
            value = value.rstrip("*")
            prefix_match = True

        if index_type == 'C' and not isinstance(value, Cidr.Cidr):
            value = Cidr.valid_cidr(value)
        else:
            value = value.strip().lower()

        if index_type == 'C' and super_prefix_match:
            return index.find_subnets(value, max)

        res = index.find(value, prefix_match, max)
        return IndexResult(res)

    def search_normal(self, value, max = 0):
        """Search for a value in the 'normal' (string keyed) indexes.
        Returns a list of object ids, or an empty list if nothing was
        found."""

        res = IndexResult()

        for attr in self.normal_indexes:
            res.extend(self.search_attr(attr, value, max))
            if max:
                if len(res) >= max:
                    res.truncate(max)
                    return res
        return res

    def search_cidr(self, value, max = 0):
        """Search for a value in the cidr indexes.  Returns a list of
        object ids, or an empty list if nothing was found."""

        res = IndexResult()
        for attr in self.cidr_indexes:
            res.extend(self.search_attr(attr, value, max))
            if max:
                if len(res) >= max:
                    res.truncate(max)
                    return res
        return res

    def search_referral(self, value, max = 0):
        """Given a heirarchal value, search for referrals.  Returns a
        list of object ids or an empty list."""

        return self.search_attr("referred-auth-area", value, max)

    def object_iterator(self):
        return self.main_index.itervalues()

class IndexResult:
    def __init__(self, list=None):
        if not list: list = []
        self.data = list
        self._dict = dict(zip(self.data, self.data))

    def extend(self, list):
        if isinstance(list, type(self)):
            list = list.list()
        new_els = [ x for x in list if not self._dict.has_key(x) ]
        self.data.extend(new_els)
        self._dict.update(dict(zip(new_els, new_els)))

    def list(self):
        return self.data

    def truncate(self, n=0):
        to_del = self.data[n:]
        for i in to_del: del self._dict[i]
        self.data = self.data[:n]


# test driver
if __name__ == "__main__":
    import sys
    db = MemDB()

    print "loading schema:", sys.argv[1]
    db.init_schema(sys.argv[1])
    for data_file in sys.argv[2:]:
        print "loading data file:", data_file
        db.load_data(data_file)
    db.index_data()

    print "Schema: authority areas"
    for a in db.authareas.keys():
        print "   %s" % a
    print "Schema: classes"
    for c in db.classes.keys():
        print "   %s" % c
    print "Schema: attributes"
    for a in db.attrs.keys():
        print "   %s" % a

    print "Is 'Network' a class?", db.is_objectclass("Network")
        
#    for k, v in db.main_index.items():
#        print "main_index[", k, "]:", v

    print "searching for a.com"
    res = db.search_attr("domain-name", "a.com")
    print res.list()
    print [ str(x) for x in db.fetch_objects(res.list()) ]

    print "searching for doe"
    res = db.search_normal("doe")
    print res.list()
    print [ str(x) for x in db.fetch_objects(res.list()) ]

    print "searching for 10.0.0.2"
    res = db.search_cidr("10.0.0.2")
    print res.list()
    print [ str(x) for x in db.fetch_objects(res.list()) ]

    print "searching for fddi.a.com"
    res = db.search_normal("fddi.a.com")
    print res.list()

    print "searching referral index for fddi.a.com"
    res = db.search_attr("referred-auth-area", "fddi.a.com")
    print res.list()
    print [ str(x) for x in db.fetch_objects(res.list()) ]


