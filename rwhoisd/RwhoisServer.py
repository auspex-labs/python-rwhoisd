# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
#
# $Id: RwhoisServer.py,v 1.3 2003/04/28 16:45:11 davidb Exp $
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

import sys, socket, SocketServer

import config, Session
import QueryParser, QueryProcessor, DirectiveProcessor, Rwhois


# server-wide variables

query_processor     = None
directive_processor = None

class RwhoisTCPServer(SocketServer.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address,
                                        RequestHandlerClass)

    def verify_request(self, request, client_address):
        # implement access control here
        return True

class RwhoisHandler(SocketServer.StreamRequestHandler):

    def readline(self):
        """Read a line of input from the client."""
        # a simple way of doing this
        # return self.rfile.readline()

        data = self.request.recv(1024)
        if not data: return None

        lines = data.splitlines(True)

        # ugh. this totally defeats any pipelining, not that rwhois
        # clients should be doing that.
        if len(lines) > 1 and config.verbose:
            print "%s discarding additional input lines: %r" \
                  % (self.client_address, lines)
        return lines[0]
        
    def handle(self):

        self.quit_flag = False

        # output a banner
        self.wfile.write(config.banner_string);
        self.wfile.write("\r\n");

        # get a session.
        session = Session.Context()
        session.rfile = self.rfile
        session.wfile = self.wfile

        if config.verbose:
            print "%s accepted connection" % (self.client_address,)

        c = 0
        while 1:
            line = self.readline()
            if not line: break

            line = line.strip()
            # we can skip blank lines.
            if not line:
                continue
            
            if line.startswith("-"):
                self.handle_directive(session, line)
            else:
                self.handle_query(session, line)
                if not session.holdconnect:
                    self.quit_flag = True

            self.wfile.flush()

            # check to see if we were asked to quit
            if self.quit_flag: break

        if config.verbose:
            print "%s disconnected" %  (self.client_address,)

    def handle_directive(self, session, line):
        if config.verbose:
            print "%s directive %s" % (self.client_address, line)
        if (line.startswith("-quit")):
            self.quit_flag = True
            self.wfile.write(Rwhois.ok())
            return
        directive_processor.process_directive(session, line)

    def handle_query(self, session, line):
        if config.verbose:
            print "%s query %s" % (self.client_address, line)
        query_processor.process_query(session, line)


def usage(pname):
    print """\
usage: %s [-v] schema_file data_file [data_file ...]
       -v: verbose """ % pname
    sys.exit(64)
    
def init(argv):
    import MemDB
    import getopt

    pname = argv[0]
    opts, argv = getopt.getopt(argv[1:], 'v')
    for o, a in opts:
        if o == "-v":
            config.verbose = True
    
    if len(argv) < 2: usage(pname)
    schema_file = argv[0]
    data_files  = argv[1:]


    db = MemDB.MemDB()

    db.init_schema(schema_file)
    for df in data_files:
        db.load_data(df)
    db.index_data()

    QueryParser.db = db

    global query_processor, directive_processor
    
    query_processor     = QueryProcessor.QueryProcessor(db)
    directive_processor = DirectiveProcessor.DirectiveProcessor(db)

def serve():
    # initialize the TCP server
    server = RwhoisTCPServer((config.server_address, config.port),
                             RwhoisHandler)

    # and handle incoming connections
    if config.verbose:
        if not config.server_address:
            print "listening on port %d" % config.port
        else:
            print "listening on %s port %d" % \
                  (config.server_address, config.port)
    server.serve_forever()

    sys.exit(0)

if __name__ == "__main__":

    init(sys.argv)
    serve()

