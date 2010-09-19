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
from vmodules import print_string



class strings2sql(forensics.commands.command):


    def help(self):
        return  "scan for processes using evasion-resistant features"

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-d', '--database',
            help='sqlite3 db to store output',
            action='store', type='string', dest='outfd1')

        self.op.add_option('-s', '--strings', help='(required) File of form <offset>:<string>',
                  action='store', type='string', dest='stringfile')

    def execute(self):
        op = self.op
        opts = self.opts
        outdb = None

        if opts.stringfile is None:
            op.error("String file (-s) required")

        try:
            strings = open(opts.stringfile, "r")
        except:
            op.error("Invalid or inaccessible file %s" % opts.stringfile)

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
                cur.execute("select * from strings")
            except sqlite3.OperationalError:
                cur.execute("create table strings(offset text, pid integer, map text, string text, memimage text)")
                conn.commit()

        else:
            print "database output file needed"
            sys.exit(0)

        (addr_space, symtab, types) = load_and_identify_image(op, opts)

        all_tasks = process_list(addr_space, types, symtab)

        # dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
        # where isKernel is True or False. if isKernel is true, list is of all kernel addresses
        # ASSUMPTION: no pages mapped in kernel and userland
        reverse_map = {} 


        vpage = 0
        while vpage < 0xFFFFFFFF:
            kpage = addr_space.vtop(vpage)
            if not kpage is None:
                if not reverse_map.has_key(kpage):
                    reverse_map[kpage] = [True]
                reverse_map[kpage].append(('kernel', vpage))
            vpage += 0x1000

        for task in all_tasks:
            process_id = process_pid(addr_space, types, task)
            process_address_space = process_addr_space(addr_space, types, task, opts.filename)
            vpage = 0
            try:
                while vpage < 0xFFFFFFFF:
                    physpage = process_address_space.vtop(vpage)
                    if not physpage is None:
                        if not reverse_map.has_key(physpage):
                            reverse_map[physpage] = [False]
                    
                        if not reverse_map[physpage][0]:
                            reverse_map[physpage].append((process_id, vpage))
                    vpage += 0x1000
            except:
                continue

        for stringLine in strings:
            (offsetString, string) = stringLine.split(':', 1)
            try:
                offset = int(offsetString)
            except:
                op.error("String file format invalid.")
            if reverse_map.has_key(offset & 0xFFFFF000):
                if outdb == None:
                    print_string(offset, reverse_map[offset & 0xFFFFF000][1:], string)
                else:
                    pidlist = reverse_map[offset & 0xFFFFF000][1:]

                    toffset = "%d" % (offset)
                    pmap = "%x" % (pidlist[0][1] | (offset & 0xFFF))
                    cur.execute("insert into strings values (?,?,?,?,?)",
                                (toffset, pidlist[0][0], pmap,  string.strip().decode('utf-8'), imgname))
                    conn.commit()
   
                    for i in pidlist[1:]:
                        pmap = "%x" % (i[1] | (offset & 0xFFF))
                        cur.execute("insert into strings values (?,?,?,?,?)", (toffset, i[0], pmap,  string.strip().decode('utf-8'), imgname))

                        conn.commit()

        conn.close()
