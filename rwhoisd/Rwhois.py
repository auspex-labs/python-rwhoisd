# This modules contains classes that are fairly general to RWhois
# server operation.

class RwhoisError(Exception):
    pass

# The RWhois error codes.  Most of these won't ever be used.
error_codes = { 120 : "Registration Deferred",
                130 : "Object Not Authoritative",
                230 : "No Objects Found",
                320 : "Invalid Attribute",
                321 : "Invalid Attribute Syntax",
                322 : "Required Attribute Missing",
                323 : "Object Reference Not Found",
                324 : "Primary Key Not Unique",
                325 : "Failed to Update Stale Object",
                330 : "Exceeded Response Limit",
                331 : "Invalid Limit",
                332 : "Nothing To Transfer",
                333 : "Not Master for Authority Area",
                336 : "Object Not Found",
                338 : "Invalid Directive Syntax",
                340 : "Invalid Authority Area",
                341 : "Invalid Class",
                342 : "Invalid Host/Port",
                350 : "Invalid Query Syntax",
                351 : "Query Too Complex",
                352 : "Invalid Security Method",
                353 : "Authentication Failed",
                354 : "Encryption Failed",
                360 : "Corrupt Data. Keyadd Failed",
                400 : "Directive Not Available",
                401 : "Not Authorized For Directive",
                402 : "Unidentified Error",
                420 : "Registration Not Authorized",
                436 : "Invalid Display Format",
                500 : "Memory Allocation Problem",
                501 : "Service Not Available",
                502 : "Unrecoverable Error",
                503 : "Idle Time Exceeded",
                560 : ""
                }

def error_message(value):
    try:
        code, msg = value
        code = int(code)
    except (TypeError, ValueError):
        try:
            code = int(value)
            msg  = None
        except ValueError:
            msg  = value
            code = 402
    if msg:
        return "%%error %d %s: %s\r\n" % \
               (code, error_codes.get(code, 402), msg)
    else:
        return "%%error %d %s\r\n" % (code, error_codes.get(code, 402))

def ok():
    return "%ok\r\n"

class rwhoisobject:
    """This is the standard class for RWhois data objects."""

    def __init__(self):
        self.data = {}
        self.attr_order = []

    def get_attr(self, attr, default=None):
        """This returns a list of values associated with a particular
        attribute.  The default value, if supplied, must be a single
        (non-sequence) value."""
        
        if default:
            return self.data.get(attr.strip().lower(), [default])
        return self.data.get(attr.strip().lower(), [])

    def get_attr_value(self, attr, default=None):
        """This returns a single value associated with the attribute.
        If the attribute has multiple values, the first is
        returned."""
        
        return self.data.get(attr.strip().lower(), [default])[0]

    def has_attr(self, attr):
        return self.data.has_key(attr.strip().lower())
    
    def getid(self):
        """Return the RWhois ID of this object."""
        
        return self.get_attr_value("id")

    def add_attr(self, attr, value):
        """Adds an attribute to the object."""
        
        attr = attr.strip().lower()
        if self.data.has_key(attr): self.data[attr].append(value)
        else:
            self.attr_order.append(attr)
            self.data.setdefault(attr, []).append(value)

    def add_attrs(self, attr_list):
        """Adds a list of (attribute, value) tuples to the object."""
        for attr, value in attr_list:
            self.add_attr(attr, value)
        
    def items(self):
        """Returns the list of (attribute, value) tuples (actually 2
        elements lists).  Attributes with multiple values produce
        multiple tuples.  The items are returned in the same order
        they were added to the object."""
        
        return [ [x, y] for x in self.attr_order for y in self.data[x] ]

    def values(self):
        """Return the list of values in this object."""
        
        return [ x for y in self.data.values() for x in y ]
    
    def __str__(self):
        """A convenient string representation of this object"""
        return '\n'.join([':'.join(x) for x in self.items()])

    def __repr__(self):
        return "<rwhoisobject: " + self.getid() + ">"
    
    def attrs_to_wire_str(self, attrs, prefix=None):
        """Return specific attributes in a response formatted string
        (classname:attr:value)"""

        cn = self.get_attr_value("class-name", "unknown-class")
        items = [ [cn, x, y] for x in attrs for y in self.data[x] ]

        if prefix:
            res = '\r\n'.join([ prefix + ':'.join(x) for x in items ])
        else:
            res = '\r\n'.join([ ':'.join(x) for x in items ])
            
        return res;

    def to_wire_str(self, prefix=None):
        """Return the response formatted string (classname:attr:value)"""

        return self.attrs_to_wire_str(self.attr_order, prefix)
    


## A basic test driver
if __name__ == '__main__':

    obj = rwhoisobject()
    obj.add_attr('id', '001')
    obj.add_attr("class-name", 'contact')
    obj.add_attr("class-name", "foo")
    obj.add_attr('name', 'Aiden Quinn')
    obj.add_attr('email', 'aquin@yahoo.com')
    obj.add_attr('org-name', 'YoYoDyne Inc.')
    obj.add_attr('email', 'aq@aol.net')
    obj.add_attr('First-Name', 'Aiden ')

    print "obj:\n", obj
    print "wire:\n", obj.to_wire_str()
