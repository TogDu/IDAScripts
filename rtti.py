#base from quarkslab ~pod2g 06/2013

from idaapi import * 
from idc import *
from string import *

addr_size = 4

first_seg = FirstSeg()
last_seg = FirstSeg()

for seg in Segments():
	if seg > last_seg:
		last_seg = seg
	if seg < first_seg:
		first_seg = seg

def get_pointer(ea):
	if addr_size == 4:
		return Dword(ea)
	else:
		return Qword(ea)

def in_image(ea):
	return ea >= first_seg and ea <= SegEnd(last_seg)
	
def class_name(ea):
	print "%08x"%ea
	mangled = GetString(ea + 4)
	if mangled == None:
		return ''
	s = Demangle('??_7' + mangled  + '6B@', 8)
	if s!= None:
		return s[:len(s)-11]
	else: 
		return GetString(ea)

def in_code(ea):
	return in_image(ea) and ea <= SegEnd(0x00401000)

def parse_typeDescriptor(ea):
	name = class_name(ea+8)
	it_id = 1
	for xref in XrefsTo(ea):
		rchd = get_pointer(xref.frm + addr_size)
		print "CompleteHeader %08x"%rchd
		if in_image(rchd):
			rcol = xref.frm - 12
			print "CompleteObject %08x [sig : %d, off :%d, cdoff %d]"%(rcol, get_pointer(rcol), get_pointer(rcol+4), get_pointer(rcol+8))
			rchd_numBaseClasses = Dword(rchd+8)
			rchd_pBaseClassArray = get_pointer(rchd+12)
			if rchd_numBaseClasses > 256:
				continue
			for i in range(rchd_numBaseClasses):
				rcbd = get_pointer(rchd_pBaseClassArray + addr_size*i)
				rcbd_pTypeDescriptor = get_pointer(rcbd)
				rcbd_pTypeDescriptor_name = class_name(rcbd_pTypeDescriptor + 8)
				print "\tbase class : %s"%(rcbd_pTypeDescriptor_name)
			for xref in XrefsTo(rcol):
				vftable = xref.frm+addr_size
				break
			print "\tvftable : %08x"%vftable
			f_id = 1
			while(in_code(get_pointer(vftable))):
				print "\t\t%s::it%d::f%d %08x"%(name, it_id, f_id, get_pointer(vftable))
				name = replace(name, "<", "_")
				name = replace(name, ">", "_")
				name = replace(name, ",", "q")
				MakeName(get_pointer(vftable), "%s::it%d::f%d"%(name,it_id, f_id))
				vftable= vftable+addr_size
				f_id = f_id + 1
			it_id = it_id+1

def scan():
	start = first_seg
	while True:
		f = FindBinary(start, SEARCH_DOWN, "2E 3F 41 56") #.?AV mangle name pattern
		start = f + addr_size
		if f == BADADDR:
			break
		rtd = f - 8 
		print "Found class : %s %08x"%(class_name(f), rtd)
		parse_typeDescriptor(rtd)