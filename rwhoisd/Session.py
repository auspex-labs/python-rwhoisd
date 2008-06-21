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

import config

class Context:
    """This class is used to hold session specific variables."""
    def __init__(self):
        # each session gets its own query parser.
        self.queryparser = None

        # these should be set by the handler
        rfile = None
        wfile = None
        
        # set some default values.
        self.limit       = config.default_limit
        self.holdconnect = False
