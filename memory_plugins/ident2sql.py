# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

import sqlite3
from vutils import *
from forensics.win32.tasks import *
from vmodules import format_time



class ident2sql(forensics.commands.command):


    def help(self):
        return  "print out identifying info"

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-d', '--database',
            help='sqlite3 db to store output',
            action='store', type='string', dest='outfd1')


    def execute(self):
        op = self.op
        opts = self.opts
        outdb = None


        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename
            temp = filename.replace("\\", "/").lower().split("/")
            imgname = temp[-1]

        if not opts.outfd1 == None:
            outdb = opts.outfd1

            conn = sqlite3.connect(outdb)
            cur = conn.cursor()

            try:
                cur.execute("select * from ident")
            except sqlite3.OperationalError:
                cur.execute("create table ident(imagetype text, vmtype text, localtime text, memimage text)")
                conn.commit()



        (addr_space, symtab, types) = load_and_identify_image(op, opts)

        ImageType = find_csdversion(addr_space, types)
        if not ImageType:
            ImageType = ""
        vmtype = ""
        if symtab == pae_syms:
            vmtype = "pae"
        else:
            vmtype = "nopae"

        KUSER_SHARED_DATA = 0xFFDF0000

        if not addr_space.is_valid_address(KUSER_SHARED_DATA):
            print "ERROR: KUSER_SHARED_DATA Invalid: Try a different Page Directory Base"
            return
    
        time = windows_to_unix_time(local_time(addr_space, types, KUSER_SHARED_DATA))
        ts = format_time(time)

        if not opts.outfd1 == None:
            cur.execute("insert into ident values(?,?,?,?)", (ImageType, vmtype, ts, imgname))
            conn.commit()
            conn.close()

        else:
            print "%25s %s" % ("Image Name:", imgname)
            print "%25s %s" % ("Image Type:", ImageType)
            print "%25s %s" % ("VM Type:", vmtype)
            print "%25s %s" % ("System Local Time:", ts)
