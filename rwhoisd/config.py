# This file is part of python-rwhoisd
#
# Copyright (C) 2003, David E. Blacka
#
# $Id: config.py,v 1.3 2003/04/28 16:44:29 davidb Exp $
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

"""Server global variables should be set here."""

import socket

##### Editable Configuration Options

# the port to listen on.
port = 4321
# the interface address to bind to. "" means INADDR_ANY.
server_address = ""

# the hostname to advertise in the banner.
server_hostname = socket.getfqdn()

# setting this here sets a default session response limit.  0
# means no response limit.  This should be between min_limit and
# max_limit defined below.
default_limit = 0
# set this to the maximum value that the limit can be set to
max_limit = 256
# set this to the minimum value that the limit can be set to
# if this is zero, you are allowing clients to disable query limits.
min_limit = 0

# If this is true, some logging will be done to stdout.
verbose = False

#### END Editable Configuration Options

version = "0.2"
banner_string = "%%rwhois V-1.5 %s (python-rwhoisd %s)" % \
                (server_hostname, version)

