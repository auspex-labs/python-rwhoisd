# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
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

import sys
import re
import Cidr
import Rwhois
import QueryParser


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
            if op == "!=":
                return not res
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
            if not self._filter_obj_term(obj, term):
                return False
        return True

    def _filter_results(self, reslist, terms):
        """Given list of result objects (not simply the ids returned
        from the search) and a list of query terms (i.e., a query
        clause), remove elements that do not satisfy the terms.
        Returns a list of objects that satisfy the filters."""

        if not terms:
            return reslist
        return [x for x in reslist if self._filter_obj(x, terms)]

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

        st = None
        sti = 0

        orig_clause = clause[:]

        # find the first searchable term:
        for term, i in zip(clause, xrange(sys.maxsize)):
            attr, op, value = term
            if op == "!=":
                continue
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

        queryres = QueryResult(objs)

        # look for referrals
        refs = self.process_referral_search(orig_clause)
        queryres.add_referrals(refs)

        return queryres

    def _is_in_autharea(self, value):
        """Returns True if value could be considered to be contained
        within an authority area.  That is, is a subnet of a
        network-type authority area or a subdomain of a domainname
        type authority area."""

        aas = self.db.get_authareas()

        if isinstance(value, Cidr.Cidr):
            for aa in aas:
                cv = Cidr.valid_cidr(aa)
                if cv and cv.is_supernet(value):
                    return True
        else:
            for aa in aas:
                if is_domainname(aa) and is_subdomain(aa, value):
                    return True
        return False

    def _referral_search_cidr(self, cv, value):
        """Return the IndexResult of a referral search for value, or
        None if the value doesn't qualify for a Cidr referral
        search."""

        if not cv:
            return None
        if not self._is_in_autharea(cv):
            return None
        return self.db.search_referral(value)

    def _referral_search_domain(self, value):
        """Return the IndexResult of a referral search for value, or
        None if the value doesn't qualify for a domain referral
        search."""

        if not is_domainname(value):
            return None
        if not self._is_in_autharea(value):
            return None
        dn = value
        res = None
        while dn:
            res = self.db.search_referral(dn)
            if res.list():
                break
            dn = reduce_domain(dn)
        return res

    def _referral_search_term(self, value):
        """Return the IndexResult of a referral search for value, or
        None if the value didn't qualify for a referral search."""

        cv = Cidr.valid_cidr(value)
        if cv:
            return self._referral_search_cidr(cv, value)
        elif is_domainname(value):
            return self._referral_search_domain(value)
        return None

    def process_referral_search(self, clause):
        """Given a query clause, attempt to search for referrals
        associated with the terms.  Return a list of referral strings
        that matched terms in the clause (if any).  The only terms
        that actually get searched are the ones that look
        'heirarchical'.  For now, the attribute part of the term is
        essentially ignored, so a search for something like
        'name=127.0.0.1' might concievably generate a referral, when
        perhaps it shouldn't."""

        # first check to see if the search is explictly for a referral
        for term in clause:
            if (term[0] == "class-name" and term[1] == "=" and term[2]
                    == "referral") or term[0] == "referred-auth-area":
                # in which case, we return nothing
                return []

        referrals = []

        # look for heirarchical-looking terms.
        for attr, op, value in clause:
            if op == "!=":
                continue
            res = self._referral_search_term(value)
            if not res or not res.list():
                continue

            ref_objs = self.db.fetch_objects(res.list())
            ref_strs = [x for y in ref_objs for x in y.get_attr("referral")]
            referrals.extend(ref_strs)

        return referrals

    def process_full_query(self, query, max=0):
        """Given a parsed query object, process it by unioning the
        results of the various ORed together clauses"""

        # shortcut for the very common single clause case:
        if len(query.clauses) == 1:
            res = self.process_query_clause(query.clauses[0], max)
            return res

        # otherwise, union the results from all the causes
        res = QueryResult()
        for clause in query.clauses:
            res.extend(self.process_query_clause(clause), max)
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
        except Rwhois.RwhoisError as x:
            session.wfile.write(Rwhois.error_message(x))
            return

        max = session.limit
        if max:
            max += 1

        query_result = self.process_full_query(query, max)

        objects = query_result.objects()
        referrals = query_result.referrals()

        if not objects and not referrals:
            session.wfile.write(Rwhois.error_message(230))
            # session.wfile.write("\r\n")
            return

        limit_exceeded = False
        if session.limit and len(objects) > session.limit:
            del objects[session.limit:]
            limit_exceeded = True

        for obj in objects:
            session.wfile.write(obj.to_wire_str())
            session.wfile.write("\r\n")

        if referrals:
            if objects:
                session.wfile.write("\r\n")
            session.wfile.write("\r\n".join(referrals))
            session.wfile.write("\r\n")

        if limit_exceeded:
            session.wfile.write(Rwhois.error_message(330))
        else:
            session.wfile.write(Rwhois.ok())


class QueryResult:

    def __init__(self, objs=[], referrals=[]):
        self.data = objs
        self.ids = [x.getid() for x in objs]
        self._dict = dict(zip(self.ids, self.ids))
        self.refs = referrals

    def extend(self, list):
        if isinstance(list, type(self)):
            list = list.objects()
        new_objs = [x for x in list if x.getid() not in self._dict]
        new_ids = [x.getid() for x in new_objs]
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
        for i in to_del:
            del self._dict[i]
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

    if match_cidr(searchval, val):
        return True

    # normalize the values for comparison.
    searchval = searchval.lower()
    val = val.lower()

    # the substring case
    if searchval.startswith("*") and searchval.endswith("*"):
        sv = searchval.strip("*")
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
        if match_value(searchval, val):
            return True
    return False


def match_cidr(searchval, val):
    """If both terms are valid CIDR values (minus any trailing
    wildcards of the search value), compare according the CIDR
    wildcard rules: subnet, supernet, and exact match.  If both terms
    are not CIDR address, return False."""

    sv = Cidr.valid_cidr(searchval.rstrip("*"))
    rv = Cidr.valid_cidr(val)

    if not sv or not rv:
        return False

    if (searchval.endswith("**")):
        return rv.is_subnet(sv)
    elif (searchval.endswith("*")):
        return rv.is_supernet(sv)
    else:
        return rv == sv


# this forms a pretty basic heuristic to see of a value looks like a
# domain name.
domain_regex = re.compile(r"[a-z0-9-]+\.[a-z0-9-.]+", re.I)


def is_domainname(value):
    if domain_regex.match(value):
        return True
    return False


def is_subdomain(domain, subdomain):
    domain = domain.lower()
    subdomain = subdomain.lower()

    dlist = domain.split('.')
    sdlist = subdomain.split('.')

    if len(dlist) > len(sdlist):
        return False
    if len(dlist) == len(sdlist):
        return domain == subdomain

    dlist.reverse()
    sdlist.reverse()

    return dlist == sdlist[:len(dlist)]


def reduce_domain(domain):
    dlist = domain.split('.')
    dlist.pop(0)
    return '.'.join(dlist)


def is_heirarchical(value):
    if cidr.valid_cidr(value):
        return True
    if is_domainname(value):
        return True
    return False


if __name__ == '__main__':

    import MemDB
    import Session

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

    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        if line.startswith("#"):
            continue

        print "parsing: '%s'" % line
        processor.process_query(session, line)
        session.wfile.write("\r\n")
        session.wfile.flush()
