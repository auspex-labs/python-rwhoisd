# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
#
# $Id: QueryParser.py,v 1.2 2003/04/28 16:43:19 davidb Exp $
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


# queryparser.db must be set to a DB class instance.
db = None

# Define the Lexer for the RWhois query language

tokens = (
    'VALUE',
    'QUOTEDVALUE',
    'CLASS',
    'ATTR',
    'AND',
    'OR',
    'EQ',
    'NEQ'
    )

# whitespace
t_ignore = ' \t'
# equality
t_EQ = r'='
# inequality
t_NEQ = r'!='

# for now, quoted values must have the wildcards inside the quotes.
# I kind of wonder if anyone would ever notice this.
t_QUOTEDVALUE = r'["\']\*?[^"*\n]+\*{0,2}["\']'

def t_firstvalue(t):
    r'^\*?[^\s"\'=*]+\*{0,2}'

    if db.is_objectclass(t.value):
        t.type = 'CLASS'
    else:
        t.type = 'VALUE'
    return t

def t_VALUE(t):
    r'\*?[^\s"\'=!*]+\*{0,2}'

    if t.value.upper() == 'AND':
        t.type = 'AND'
        t.value = t.value.upper()
        return t
    if t.value.upper() == 'OR':
        t.type = 'OR'
        t.value = t.value.upper()
        return t
    if db.is_attribute(t.value):
        t.type = 'ATTR'
    else:
        t.type = 'VALUE'
    return t


def t_error(t):
    pass
    # print "Illegal character '%r'" % t.value[0]
    # t.type = 'ERR'
    # t.skip(1)

# initalize the lexer
import lex
lex.lex()

# Define the parser for the query language

# 'value' productions are simple strings
# 'querystr' productions are tuples (either 1 or 3 values)
# 'query' productions are Query objects
# 'total' productions are Query objects

def p_total_class_query(t):
    'total : CLASS query'

    t[0] = t[2]
    t[0].set_class(t[1])

def p_total_query(t):
    'total : query'

    t[0] = t[1]


def p_query_oper_querystr(t):
    '''query : query AND querystr
             | query OR  querystr'''

    t[0] = t[1]
    if t[2] == 'OR':
        t[0].cur_clause  = [ t[3] ]
        t[0].clauses.append(t[0].cur_clause)
    else:
        t[0].cur_clause.append(t[3])

def p_query_querystr(t):
    'query : querystr'

    t[0] = Query()
    t[0].cur_clause = [ t[1] ]
    t[0].clauses.append(t[0].cur_clause)

def p_querystr_attr_value(t):
    '''querystr : ATTR EQ value
                | ATTR NEQ value'''

    t[0] = (t[1], t[2], t[3])

def p_querystr_attr(t):
    'querystr : ATTR'

    t[0] = (None, '=', t[1])

def p_querystr_value(t):
    'querystr : value'

    t[0] = (None, '=', t[1])


def p_value(t):
    'value : VALUE'

    t[1] = t[1].strip()
    if t[1]:
        t[0] = t[1]

def p_quotedvalue(t):
    'value : QUOTEDVALUE'

    t[0] = t[1].strip('"')


def p_error(t):
     # print "Syntax error at '%s:%s'" % (t.type, t.value)
     raise yacc.YaccError, "Syntax error at %r" % t.value

    
import types
class Query:
    """A representation of a parsed RWhois query."""
    
    def __init__(self):
        self.clauses     = []
        self.cur_clause  = None
        self.objectclass = None
        self.prepared    = False
        
    def __str__(self):
        self._prepare()
        res = ''
        for i in range(len(self.clauses)):
            cl = self.clauses[i]
            res += "clause %d:\n" % i
            for item in cl:
                res += "  " + repr(item) + "\n"
        return res

    def __repr__(self):
        return "<Query:\n" + str(self) + ">"

    def _prepare(self):
        """Prepare the query for use.  For now, this means propagating
        an objectclass restriction to all query clauses."""
        
        if self.prepared: return
        if self.objectclass:
            for c in self.clauses:
                c.append(("class-name", "=", self.objectclass))

    def clauses(self):
        """Return the query clauses.  This is a list of AND clauses,
        which are, in turn, lists of query terms.  Query terms are 3
        element tuples: (attr, op, value)."""
        
        return self.clauses
    
    def set_class(self, objectclass):
        """Set the query-wide objectclass restriction."""

        # note: we don't allow the code to set this more than once,
        # because we would have to code the removal of the previous
        # class restriction from the query clauses, and it just isn't
        # worth it.  Queries are built, used and thrown away.
        assert not self.prepared
        self.objectclass = objectclass
        return


import yacc
import Rwhois

def get_parser():
    """Return a parser instances.  Parser objects should not be shared
    amongst threads."""

    return yacc.yacc()

def parse(p, query):
    """Parse a query, raising a RwhoisError in case of parse failure.
    Returns a Query object."""

    # before using any parser objects, the database backend must be
    # set (and it shared by all parsers).
    assert db
    try:
        return p.parse(query)
    except (lex.LexError, yacc.YaccError):
        raise Rwhois.RwhoisError, (350, "")

if __name__ == "__main__":
    import sys
    import MemDB

    mydb = MemDB.MemDB()

    print "loading schema:", sys.argv[1]
    mydb.init_schema(sys.argv[1])
    for data_file in sys.argv[2:]:
        print "loading data file:", data_file
        mydb.load_data(data_file)
    mydb.index_data()

    db = mydb
    qp = get_parser()
    
    for line in sys.stdin.readlines():
        line = line.rstrip('\n')
        line = line.strip()
        if not line: continue
        print 'inputting:', `line`
        try:
            res = qp.parse(line)
            print repr(res)
        except (lex.LexError, yacc.YaccError), x:
            print "parse error occurred:", x
            print "query:", line


#         lex.input(line)
#         while 1:
#             tok = lex.token()
#             if not tok: break
#             print tok
        
    
