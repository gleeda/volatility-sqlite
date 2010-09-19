# Volatility
# Copyright (C) 2008 Volatile Systems
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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

import sqlite3
from vutils import *
from forensics.win32.scan2 import GenMemScanObject, PoolScanner#, PoolScanProcessFast2
from forensics.win32.scan2 import scan_addr_space
import forensics.win32.meta_info as meta_info

outfd = None
imgname = None

class PoolScanProcessFast2SQL(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x50\x72\x6F\xE3"
        self.pool_size = 0x280

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_geq)
            self.add_constraint(self.check_pooltype)
            self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_dtb)
            self.add_constraint(self.check_dtb_aligned)
            self.add_constraint(self.check_thread_list)

        def check_dtb(self, buff, found):
            poffset = self.object_offset(found)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], poffset)
            if DirectoryTableBase == 0:
                return False
            if DirectoryTableBase == None:
                return False
            return True

        def check_dtb_aligned(self, buff, found):
            poffset = self.object_offset(found)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], poffset)
            if DirectoryTableBase == None:
                return False
            if (DirectoryTableBase % 0x20) != 0:
                return False
            return True

        def object_offset(self,found):
            (offset, tmp) = get_obj_offset(self.data_types, ['_OBJECT_HEADER', 'Body'])
            return (found - 4) + obj_size(self.data_types,'_POOL_HEADER') + offset

        def check_thread_list(self, buff, found):
            kernel = 0x80000000

            poffset = self.object_offset(found)
            thread_list_head_flink =  read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS','ThreadListHead', 'Flink'], poffset)

            if thread_list_head_flink < kernel:
                return False

            thread_list_head_blink =  read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'ThreadListHead', 'Blink'], poffset)

            if thread_list_head_blink < kernel:
                return False

            return True

        def object_action(self,buff,object_offset, outfd):
            """
            In this instance, the object action is to print to
            stdout
            """
            
            UniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'UniqueProcessId'], object_offset)
            InheritedFromUniqueProcessId = read_obj_from_buf(buff, self.data_types, \
               ['_EPROCESS', 'InheritedFromUniqueProcessId'], object_offset)
            DirectoryTableBase  = read_obj_from_buf(buff, self.data_types, \
                ['_EPROCESS', 'Pcb', 'DirectoryTableBase', 0], object_offset)

            address = self.as_offset + object_offset


            (file_name_offset, current_type) = get_obj_offset(self.data_types,\
                ['_EPROCESS', 'ImageFileName'])

            fnoffset = object_offset+file_name_offset
            string = buff[fnoffset:fnoffset+256]
            if (string.find('\0') == -1):
                ImageFileName = string
            else:
                (ImageFileName, none) = string.split('\0', 1)

            create_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'CreateTime'],object_offset)

            exit_time = read_time_buf(buff,self.data_types,\
                ['_EPROCESS', 'ExitTime'],object_offset)

            if create_time == 0:
                CreateTime = ""
            else:
                CreateTime = self.format_time(create_time)

            if exit_time == 0:
                ExitTime = ""
            else:
                ExitTime = self.format_time(exit_time)

            if not outfd == None:
                conn = sqlite3.connect(outfd)
                cur = conn.cursor()
                a = "0x%0.8x" % (address)
                dtb = "0x%0.8x" % (DirectoryTableBase)
                try:
                    cur.execute("insert into psscan3 values (?,?,?,?,?,?,?,?)", 
                        (UniqueProcessId,InheritedFromUniqueProcessId,CreateTime,
                        ExitTime,a,dtb,ImageFileName.lower(), imgname))
                    conn.commit()
                except sqlite3.ProgrammingError,UnicodeDecodeError:
                    #seems to only get here after it has run for a long time and already found the "sytem" process
                    pass

            print "%6d %6d %24s %24s 0x%0.8x 0x%0.8x %-16s"% \
                 (UniqueProcessId,InheritedFromUniqueProcessId,CreateTime,\
                 ExitTime,address,DirectoryTableBase,ImageFileName.lower())
            
            #this is to keep the script from running crashing (with sqlite) after it has found the 'system' process
            if outfd != None and UniqueProcessId == 4 and InheritedFromUniqueProcessId == 0 and ImageFileName.lower() == 'system':
                print "output saved to %s sqlite db" % (outfd)
                sys.exit(0)

class RobustPsScanner(PoolScanner):
    def __init__(self, poffset, outer):
        PoolScanner.__init__(self, poffset, outer)
        self.sz = outer.pool_size

    def check_addr(self,buff,found):
        cnt = 0
        for func in self.constraints:
            val = func(buff,found)
            if val == True:
                cnt = cnt+1
            else:
                return cnt
        return cnt

    # Need to override process_buffer since we don't want to
    # check pool tags
    def process_buffer(self, buf, poffset, metadata=None):
        if poffset + self.sz >= self.outer.addr_space.fsize:
            return

        for i in range(0, (len(buf)-self.sz)+1, 8):
            match_count = self.check_addr(buf, i)
            if match_count == self.get_limit():
                self.matches.append(poffset+i)
                self.object_action(buf,i)

class ProcessScanFast3(GenMemScanObject):
    def __init__(self, addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_size = obj_size(types, '_EPROCESS')
        self.matches = []

    class Scan(RobustPsScanner,PoolScanProcessFast2SQL.Scan):
        def __init__(self, poffset, outer):
            RobustPsScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_ws_lock_count)
            self.add_constraint(self.check_ac_lock_count)
            self.add_constraint(self.check_dtb)
            self.add_constraint(self.check_dtb_aligned)
            self.add_constraint(self.check_granted_access)
            self.add_constraint(self.check_vadroot)
            self.add_constraint(self.check_object_table)
            self.add_constraint(self.check_threadlist_flink)
            self.add_constraint(self.check_pcb_threadlist_flink)
            self.add_constraint(self.check_readylist_flink)
            self.add_constraint(self.check_wsl)

        def object_action(self, buf, found):
            PoolScanProcessFast2SQL.Scan.object_action(self, buf, found, outfd)
        
        def object_offset(self, found):
            return found

        def check_in_kernel(self, buf, field, found):
            kernel = 0x80000000
            val = read_obj_from_buf(buf, types, field, found)
            return val >= kernel

        def check_granted_access(self, buf, found):
            granted_access = read_obj_from_buf(buf, types, ['_EPROCESS','GrantedAccess'], found)
            return (granted_access & 0x1f07fb) == 0x1f07fb
        
        def check_vadroot(self, buf, found):
            field = ['_EPROCESS', 'VadRoot']
            if self.check_in_kernel(buf, field, found):
                return True
            else:
                val = read_obj_from_buf(buf, types, field, found)
                if val == 0:
                    return True
                else:
                    return False
        
        def check_object_table(self, buf, found):
            field = ['_EPROCESS','ObjectTable']
            return self.check_in_kernel(buf, field, found)

        def check_threadlist_flink(self, buf, found):
            field = ['_EPROCESS','ThreadListHead','Flink']
            return self.check_in_kernel(buf, field, found)

        def check_pcb_threadlist_flink(self, buf, found):
            field = ['_EPROCESS','Pcb','ThreadListHead','Flink']
            return self.check_in_kernel(buf, field, found)

        def check_readylist_flink(self, buf, found):
            field = ['_EPROCESS','Pcb','ReadyListHead','Flink']
            return self.check_in_kernel(buf, field, found)

        def check_wsl(self, buf, found):
            field = ['_EPROCESS','Vm','VmWorkingSetList']
            val = read_obj_from_buf(buf, types, field, found)
            return val >= 0xc0000000
        
        def check_ws_lock_count(self, buf, found):
            field = ['_EPROCESS','WorkingSetLock','Count']
            val = read_obj_from_buf(buf, types, field, found)
            return val == 1

        def check_ac_lock_count(self, buf, found):
            field = ['_EPROCESS','AddressCreationLock','Count']
            val = read_obj_from_buf(buf, types, field, found)
            return val == 1

class psscan3sql(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'brendandg@gatech.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def help(self):
        return  "scan for processes using evasion-resistant features"

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

            conn = sqlite3.connect(outfd)
            cur = conn.cursor()

            try:
                cur.execute("select * from psscan3")
            except sqlite3.OperationalError:
                cur.execute("create table psscan3(pid integer, ppid integer, ctime text, etime text, offset text, pdb text, pname text, memimage text)")
                conn.commit()
    
            conn.close()

        else:
            outfd = None
            
        from vtypes import xpsp2types
        xpsp2types['_FAST_MUTEX'][1]['Count'] = [ 0x0, ['long']]
        xpsp2types['_EPROCESS'][1]['GrantedAccess'] = [ 0x1a4, ['unsigned long']]
        xpsp2types['_EPROCESS'][1]['Vm'] = [ 0x1f8, ['_MMSUPPORT']]
        xpsp2types['_KPROCESS'][1]['ThreadListHead'] = [ 0x50, ['_LIST_ENTRY']]
        xpsp2types['_KPROCESS'][1]['ReadyListHead'] = [ 0x40, ['_LIST_ENTRY']]
        xpsp2types['_MMSUPPORT'] = [ 0x40, {'VmWorkingSetList' : [ 0x20, ['pointer', ['_MMWSL']]]} ]

        meta_info.set_datatypes(xpsp2types)

        scanners = []
        space = FileAddressSpace(self.opts.filename)
        search_space = space
        print "PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n"+ \
              "------ ------ ------------------------ ------------------------ ---------- ---------- ----------------";
        scanners.append((ProcessScanFast3(search_space)))
        scan_addr_space(search_space,scanners)
        
