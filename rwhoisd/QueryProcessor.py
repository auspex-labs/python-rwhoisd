import sys
import Cidr, Rwhois, QueryParser

class QueryProcessor:

    def __init__(self, db):
        self.db = db

    def _filter_obj_term(self, obj, term):
        """Given a rwhoisobject and a query term (a 3 element tuple:
        attr, operator, value), determine if the object satisfies the
        term.  Returns True if the object matches the term, False if
        not."""

        attr, op, searchval = term
        res = False

        # filter by named attribute
        if attr:
            vals = obj.get_attr(attr)
            if not vals:
                res = False
            else:
                res = match_values(searchval, vals)
            if op == "!=": return not res
            return res
        # filter by general term
        else:
            for val in obj.values():
                if match_value(searchval, val):
                    return True
            return False

    def _filter_obj(self, obj, terms):
        """Given a rwhoisobject and a list of query terms (i.e., a
        whole AND clause), return True if the object satisfies the
        terms."""

        for term in terms:
            if not self._filter_obj_term(obj, term): return False
        return True

    def _filter_results(self, reslist, terms):
        """Given list of result objects (not simply the ids returned
        from the search) and a list of query terms (i.e., a query
        clause), remove elements that do not satisfy the terms.
        Returns a list of objects that satisfy the filters."""

        if not terms: return reslist
        return [ x for x in reslist if self._filter_obj(x, terms) ]

    def process_query_clause(self, clause, max=0):
        """Process a query clause (a grouping of terms ANDed
        together).  This is where the indexed searches actually get
        done.  The technique used here is to search on one index and
        use the rest of the clause to filter the results.  Returns a
        QueryResult object"""

        # the technique is to do an index search on the first (or
        # maybe best) indexed term (bare terms are always considered
        # indexed), and filter those results with the remaining terms.

        # Note: this could be better if we found the "optimal" query
        # term.  One approach may be to create a cost function and
        # search for the minimum cost term.

        # Note: another approach might be to actually do indexed
        # searches on all applicable terms (bare or using an indexed
        # attribute) and find the intersection of the results.

        # FIXME: need to put in the referral chasing logic here, I
        # think.
        
        st  = None
        sti = 0

        # find the first searchable term:
        for term, i in zip(clause, xrange(sys.maxint)):
            attr, op, value = term
            if op == "!=": continue
            if not attr or self.db.is_indexed_attr(attr):
                st, sti = term, i
                break
        if not st:
            raise Rwhois.RwhoisError, (351, "No indexed terms in query clause")

        # remove the search term from the clause, what remains is the
        # filter.
        del clause[sti]

        # if we have an attribute name, search on that.
        if st[0]:
            res = self.db.search_attr(st[0], st[2], max)
        else:
            if Cidr.valid_cidr(st[2].strip("*")):
                res = self.db.search_cidr(st[2], max)
            else:
                res = self.db.search_normal(st[2], max)

        objs = self._filter_results(self.db.fetch_objects(res.list()), clause)

        return QueryResult(objs)

    def process_full_query(self, query, max=0):
        """Given a parsed query object, process it by unioning the
        results of the various ORed together clauses"""

        # shortcut for the very common single clause case:
        if len(query.clauses) == 1:
            res = self.process_query_clause(query.clauses[0])
            return res

        res = QueryResult()
        for clause in query.clauses:
            res.extend(self.process_query_clause(clause))
            if max and len(res) >= max:
                res.truncate(max)
                break

        return res

    def process_query(self, session, queryline):
        """Given a session config and a query line, parse the query,
        perform any searches, return any referrals."""
        
        if not session.queryparser:
            session.queryparser = QueryParser.get_parser()

        # parse the query
        try:
            query = QueryParser.parse(session.queryparser, queryline)
        except Rwhois.RwhoisError, x:
            session.wfile.write(Rwhois.error_message(x))
            return
        
        max = session.limit
        if max: max += 1

        query_result = self.process_full_query(query, max)

        objects   = query_result.objects()
        referrals = query_result.referrals()
        
        if not objects and not referrals:
            session.wfile.write(Rwhois.error_message(230))
            # session.wfile.write("\r\n")
            return

        for obj in objects:
            session.wfile.write(obj.to_wire_str())
            session.wfile.write("\r\n")

        if referrals:
            session.wfile.write("\r\n".join(referrals))
            session.wfile.write("\r\n")
                                
        if session.limit and len(objects) > session.limit:
            session.wfile.write(330)
        else:
            session.wfile.write(Rwhois.ok())

class QueryResult:

    def __init__(self, objs=[], referrals=[]):
        self.data  = objs
        self.ids   = [ x.getid() for x in objs ]
        self._dict = dict(zip(self.ids, self.ids))
        self.refs  = referrals

    def extend(self, list):
        if isinstance(list, type(self)):
            list = list.objects()
        new_objs = [ x for x in list if not self._dict.has_key(x.getid()) ]
        new_ids = [ x.getid() for x in new_objs ]
        self.data.extend(new_objs)
        self.ids.extend(new_ids)
        self._dict.update(dict(zip(new_ids, new_ids)))

    def add_referrals(self, referrals):
        self.refs.extend(referrals)
    
    def objects(self):
        return self.data

    def referrals(self):
        return self.refs
    
    def ids(self):
        return self.ids

    def truncate(self, n=0):
        to_del = self.ids[n:]
        for i in to_del: del self._dict[i]
        self.ids = self.ids[:n]
        self.data = self.data[:n]

        
def match_value(searchval, val):
    """Determine if a search value matches a data value.  If both
    matching terms are valid CIDR objects, then they are matched
    according the CIDR wildcard rules (i.e., a single trailing * is a
    supernet search, ** is a subnet search).  If the search value is
    not wildcarded, then they are just tested for numeric equality.
    Otherwise, the terms are compared using string semantics
    (substring, prefix, suffix, and exact match."""

    if match_cidr(searchval, val): return True

    # normalize the values for comparison.
    searchval = searchval.lower()
    val = val.lower()

    # the substring case
    if searchval.startswith("*") and searchval.endswith("*"):
        sv = searchval.strip("*");
        if val.find(sv) >= 0:
            return True
        else:
            return False
    # the suffix case
    elif searchval.startswith("*"):
        sv = searchval.lstrip("*")
        return val.endswith(sv)
    # the prefix case
    elif searchval.endswith("*"):
        sv = searchval.rstrip("*")
        return val.startswith(sv)
    # the exact match case
    else:
        return searchval == val

def match_values(searchval, val_list):

    for val in val_list:
        if match_value(searchval, val): return True
    return False

def match_cidr(searchval, val):
    """If both terms are valid CIDR values (minus any trailing
    wildcards of the search value), compare according the CIDR
    wildcard rules: subnet, supernet, and exact match.  If both terms
    are not CIDR address, return False."""


    sv = Cidr.valid_cidr(searchval.rstrip("*"))
    rv = Cidr.valid_cidr(val)

    if not sv or not rv: return False

    if (searchval.endswith("**")):
        return rv.is_subnet(sv)
    elif (searchval.endswith("*")):
        return rv.is_supernet(sv)
    else:
        return rv == sv


if __name__ == '__main__':

    import MemDB, Session
    
    db = MemDB.MemDB()

    print "loading schema:", sys.argv[1]
    db.init_schema(sys.argv[1])
    for data_file in sys.argv[2:]:
        print "loading data file:", data_file
        db.load_data(data_file)
    db.index_data()

    QueryParser.db = db
    processor = QueryProcessor(db)

    session = Session.Context()
    session.wfile = sys.stdout
    
    while 1:
        line = sys.stdin.readline().strip();
        if not line: break
        if line.startswith("#"): continue

        print "parsing: '%s'" % line
        processor.process_query(session, line)
        session.wfile.write("\r\n");
        session.wfile.flush()
