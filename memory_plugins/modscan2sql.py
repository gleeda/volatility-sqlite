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
from vutils import *
from forensics.win32.scan2 import GenMemScanObject, PoolScanner
from forensics.win32.scan2 import scan_addr_space
import forensics.win32.meta_info as meta_info

outfd = None
imgname = None

class PoolScanModuleFast2SQL(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x4D\x6D\x4C\x64" 
        self.pool_size = 0x4c

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)

        def module_pool_imagename(self, buff, mod_offset):
            addr_space = meta_info.KernelAddressSpace
            name_buf = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName', 'Buffer'], mod_offset)
            name_buf_len = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName', 'Length'], mod_offset)
    
            readBuf = read_string(addr_space, self.data_types, ['char'], \
                name_buf, name_buf_len)
            if readBuf is None:
                imagename = ""

            try:
                imagename = readBuf.decode('UTF-16').encode('ascii', 'backslashreplace')
            except:
                imagename = ""

            return imagename

        def module_pool_modulename(self, buff, mod_offset):
            addr_space = meta_info.KernelAddressSpace
            name_buf = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName', 'Buffer'], mod_offset)
            name_buf_len = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName', 'Length'], mod_offset)

            readBuf = read_string(addr_space, self.data_types, ['char'], \
                name_buf, name_buf_len)
            if readBuf is None:
                modulename = ""
            try:
                modulename = readBuf.decode('UTF-16').encode('ascii', 'backslashreplace')
            except:
                modulename = ""

            return modulename


        def object_action(self,buff,object_offset):
            """
            In this instance, the object action is to print to
            stdout
            """
            system_addr_space = meta_info.KernelAddressSpace

            baseaddr = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], object_offset)
            imagesize = read_obj_from_buf(buff, self.data_types, \
                ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], object_offset)

            imagename   = self.module_pool_imagename(buff, object_offset)
            modulename  = self.module_pool_modulename(buff, object_offset)
            print "%-50s 0x%010x 0x%06x %s" % \
                (imagename, baseaddr, imagesize, modulename)

            if not outfd == None:
                b = "0x%010x" % (baseaddr)
                i = "0x%06x" % (imagesize)
                conn = sqlite3.connect(outfd)
                cur = conn.cursor()
                cur.execute("insert into modscan2 values (?,?,?,?,?)", 
                            (imagename.lower(), b, i, modulename.lower(), imgname))
                conn.commit()


class modscan2sql(forensics.commands.command): 
    def help(self):
        return  "scan for module objects"

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-d', '--database',
            help='sqlite3 db to store output',
            action='store', type='string', dest='outfd1')

    def execute(self):

        scanners = [] 
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

            conn = sqlite3.connect(outfd)
            cur = conn.cursor()

            try:
                cur.execute("select * from modscan2")
            except sqlite3.OperationalError:
                cur.execute("create table modscan2 (file text, base text, size text, name text, memimage text)")
                conn.commit()

            conn.close()

        else:
            outfd = None

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

        print "%-50s %-12s %-8s %s \n"%('File','Base', 'Size', 'Name')

        scanners.append((PoolScanModuleFast2SQL(search_address_space)))
        scan_addr_space(search_address_space,scanners)
