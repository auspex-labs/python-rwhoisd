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

import re
import Rwhois, config

class DirectiveProcessor:

    rwhois_dir_exp = re.compile(r"V-(\d+\.\d+)", re.I)

    def __init__(self, db):
        self.db = db
        self.directives = {
            "rwhois" : self.rwhois_directive,
            "limit"  : self.limit_directive,
            "holdconnect" : self.hold_directive,
            "directive" : self.directive_directive,
            "xfer" : self.xfer_directive,
            "status" : self.status_directive
            }

    def process_directive(self, session, line):
        d_args = line.lstrip("-").split()

        if not self.directives.has_key(d_args[0]):
            session.wfile.write(Rwhois.error_message(400))
            return

        self.directives[d_args[0]](session, d_args[1:])


    def rwhois_directive(self, session, arglist):
        if not arglist:
            session.wfile.write(Rwhois.error_message(338))
            return
        
        mo = DirectiveProcessor.rwhois_dir_exp.match(arglist[0])
        if not mo:
            session.wfile.write(Rwhois.error_message(338))
            return

        # normally we would make sure that the version given was
        # sufficiently great.

        session.wfile.write(config.banner_string)
        session.wfile.write("\r\n")

    def limit_directive(self, session, arglist):
        try:
            limit = int(arglist[0])
        except (IndexError, ValueError):
            session.wfile.write(Rwhois.error_message(338))
            return
        
        if limit > config.max_limit:
            limit = config.max_limit
        elif limit < config.min_limit:
            limit = config.min_limit
        session.limit = limit

        session.wfile.write(Rwhois.ok())

    def hold_directive(self, session, arglist):
        if not arglist:
            session.wfile.write(Rwhois.error_message(338))
            return
        
        arg = arglist[0].lower()
        if arg == "on":
            session.holdconnect = True
        elif arg == "off":
            session.holdconnect = False
        else:
            session.wfile.write(Rwhois.error_message(338))
            return
        
        session.wfile.write(Rwhois.ok())

    def directive_directive(self, session, arglist):
        if not arglist:
            reslist = []
            dirs = self.directives.keys()
            dirs.sort()
            for dir in dirs:
                desc = dir.capitalize()
                reslist.append("%%directive directive:%s" % dir)
                reslist.append("%%directive description:%s directive" % desc)
            session.wfile.write("\r\n".join(reslist))
            session.wfile.write("\r\n")
            session.wfile.write(Rwhois.ok())
            return
        if self.directives.has_key(arglist[0]):
            dir = arglist[0]
            desc = dir.capitalize()
            session.wfile.write("%%directive directive:%s\r\n" % dir)
            session.wfile.write("%%directive description:%s directive\r\n"
                                % desc)
        else:
            session.wfile.write(Rwhois.error_message(400))
            return
        session.wfile.write(Rwhois.ok())


    def status_directive(self, session, arglist):
        if session.holdconnect:
            hc_str = "on"
        else:
            hc_str = "off"

        session.wfile.write("%%status limit: %d\r\n" % session.limit)
        session.wfile.write("%%status holdconnect: %s\r\n" % hc_str)
        session.wfile.write("%status forward: off\r\n")
        session.wfile.write("%%status objects: %d\r\n" 
                            % len(self.db.main_index))
        session.wfile.write("%status display: dump\r\n")
        session.wfile.write("%status contact: N/A\r\n")
        session.wfile.write(Rwhois.ok())
        
    def xfer_directive(self, session, arglist):
        if not arglist:
            session.wfile.write(Rwhois.error_message(338))
            return
        
        aa = arglist[0].lower()

        oc = None
        attr_list = []
        for arg in arglist[1:]:
            if arg.startswith("class="):
                oc = arg[6:].lower()
            elif arg.startswith("attribute="):
                attr = arg[10:].lower()
                if attr: attr_list.append(attr)

        # check the constraints
        if not self.db.is_autharea(aa):
            session.wfile.write(Rwhois.error_message((340, aa)))
            return
        if oc and not self.db.is_objectclass(oc):
            session.wfile.write(Rwhois.error_message((341, oc)))
            return

        for attr in attr_list:
            if not self.db.is_attribute(attr):
                session.wfile.write(Rwhois.error_message((342, attr)))
                return

        # now iterate over the entire dataset looking for objects that
        # match our criteria.

        objs = self.db.object_iterator()

        for obj in objs:
            # Note: in theory, we should leverage QueryProcessors
            # filtering code.
            if obj.get_attr_value("auth-area").lower() != aa:
                continue
            if oc and obj.get_attr_value("class-name").lower() != oc:
                continue

            if attr_list:
                session.wfile.write(obj.attrs_to_wire_str(attr_list, "%xfer "))
            else:
                session.wfile.write(obj.to_wire_str("%xfer "))
            session.wfile.write("\r\n%xfer \r\n");
            
        session.wfile.write(Rwhois.ok())
        

if __name__ == '__main__':

    import sys
    import MemDB
    
    session = Session.Context()
    session.wfile = sys.stdout

    db = MemDB.MemDB()

    db.init_schema(sys.argv[1])
    for data_file in sys.argv[2:]:
        db.load_data(data_file)
    db.index_data()

    dp = DirectiveProcessor(db)

    directives = [ "-rwhois",
                   "-rwhois foo bar baz",
                   "-rwhois V-1.6 noise blah",
                   "-limit",
                   "-limit a",
                   "-limit 20",
                   "-holdconnect",
                   "-holdconnect on",
                   "-holdconnect foo",
                   "-directive",
                   "-directive limit",
                   "-directive foo",
                   "-xfer",
                   "-xfer a.com",
                   "-xfer a.com class=contact",
                   "-xfer a.com class=domain attribute=domain-name",
                   "-xfer foo class=bar",
                   "-xfer foo class=bar attribute=baz attribute=boo",
                   "-foo baz bar" ]

    for dir in directives:
        print "trying %r:" % dir
        print dp.process_directive(session, dir)

