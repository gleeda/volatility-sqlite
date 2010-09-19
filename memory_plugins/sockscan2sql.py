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

import sys 
import os
import sqlite3
from forensics.win32.network import *
from vutils import *
from forensics.win32.scan2 import GenMemScanObject, PoolScanner
from forensics.win32.scan2 import scan_addr_space
import forensics.win32.meta_info as meta_info


class PoolScanSockFast2SQL(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x54\x43\x50\x41" 
        self.pool_size = 0x170
    #self.pool_size = 0x158

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_equal)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_socket_create_time)

        def check_socket_create_time(self, buff, found):
            soffset = self.object_offset(found)

            time = read_time_buf(buff,self.data_types,\
                ['_ADDRESS_OBJECT', 'CreateTime'],soffset)

            if time == None:
                return False

            if time > 0:
                return True
            return False

        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            pid = read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'Pid'], object_offset)
            proto = read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'Protocol'], object_offset)
            port = ntohs(read_obj_from_buf(buff, self.data_types, \
                ['_ADDRESS_OBJECT', 'LocalPort'], object_offset))

            time = read_time_buf(buff,self.data_types,\
                ['_ADDRESS_OBJECT', 'CreateTime'],object_offset)

            ooffset = self.as_offset + object_offset
            try:
                print "%-6d %-6d %-6d %-26s 0x%0.8x"%(pid,port,proto, \
                    self.format_time(time),ooffset)
                if not outfd == None:
                    myo = "0x%0.8x" % (ooffset)
                    conn = sqlite3.connect(outfd)
                    cur = conn.cursor()
                    cur.execute("insert into sockscan2 values (?,?,?,?,?,?)",
                            (pid, port, proto, self.format_time(time), myo, imgname))
                    conn.commit()

            except:
                return


class sockscan2sql(forensics.commands.command):
    def help(self):
        return  "scan for socket objects"

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-d', '--database',
            help='sqlite3 db to store output',
            action='store', type='string', dest='outfd1')

    def execute(self):
        op = self.op
        opts = self.opts

        global imgname

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename
            temp = filename.replace("\\", "/").lower().split("/")
            imgname = temp[-1]

        global outfd
        if not opts.outfd1 == None:
            outfd = opts.outfd1
            print outfd

            conn = sqlite3.connect(outfd)
            cur = conn.cursor()

            try:
                cur.execute("select * from sockscan2")
            except sqlite3.OperationalError:
                cur.execute("create table sockscan2(pid integer, port integer, proto text, ctime text, offset text, memimage text)")
                conn.commit()
    
            conn.close()

        else:
            outfd = None
 
        scanners = [] 

        try: 
            flat_address_space = FileAddressSpace(filename,fast=True)
        except:
            op.error("Unable to open image file %s" % (filename))
    
        meta_info.set_datatypes(types)

        # Determine the applicable address space
        search_address_space = find_addr_space(flat_address_space, types)

        # Find a dtb value
        if opts.base is None:
            sysdtb = get_dtb(search_address_space, types)
        else:
            try: 
                sysdtb = int(opts.base, 16)
            except:
                op.error("Directory table base must be a hexidecimal number.")

        meta_info.set_dtb(sysdtb)
        kaddr_space = load_pae_address_space(filename, sysdtb)
        if kaddr_space is None:
            kaddr_space = load_nopae_address_space(filename, sysdtb)
        meta_info.set_kas(kaddr_space)

        print "PID    Port   Proto  Create Time                Offset \n"+ \
            "------ ------ ------ -------------------------- ----------\n";

        scanners.append(PoolScanSockFast2SQL(search_address_space))
        scan_addr_space(search_address_space,scanners)
