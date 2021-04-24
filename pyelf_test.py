import struct
import sys
import random
from capstone import *
from elftools.elf.elffile import ELFFile


#define ONEBYTE_SYM       x86DisassemblerOneByteOpcodes
#define TWOBYTE_SYM       x86DisassemblerTwoByteOpcodes


def get_disasm_length(code):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	last_instr = 0
	for i in md.disasm(code, 0x0000):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
		#print("...and size: {}".format(i.size))			
		last_instr = i
	if last_instr != 0:
		disasm_length = last_instr.address + last_instr.size
		#print("Amount of correctly disassemled bytes: {} :)".format(disasm_bytes))
		return disasm_length

	print("Error: No bytes correctly disassembled :(")
	return 0
	
	
	
def insert_junk_bytes(code, junk_bytes):
	"""
	Currently confined to junk_bytes of length one or two.
	"""
	desync_code = bytearray(code)
	
	if len(junk_bytes) == 1:
		desync_code[0] = junk_bytes
	#else:
	#	desync_code[0] = junk_bytes
	
	return bytes(desync_code)
	
	
	
def find_junk_bytes(pos_single_bytes, pos_double_bytes):
	"""
	Currently confined to junk_bytes of length one or two.
	"""
	junk_bytes = -1
	if not pos_single_bytes:
		i = random.randrange(len(pos_single_bytes)-1)
		junk_bytes = pos_single_bytes.pop(i)
	#elif not pos_double_bytes:
	#	i = random.randrange(len(pos_double_bytes))
	#	junk_bytes = pos_double_bytes.pop(i)
		return (bytes([junk_bytes]), pos_single_bytes)
	return (junk_bytes, pos_single_bytes)
	
	
	
def get_pos_bytes_lists():
	#from capstone get list of single byters
	#C = list(set(A)) # - set(B))
	pos_bytes = list(range(0, 256))
	return pos_bytes

	

def main():
	
	#!/usr/bin/python3

	binary = sys.argv[1]
	arg_symbol = sys.argv[2]


	with open(binary, 'rb') as f:
		elf = ELFFile(f)
		symtab = elf.get_section_by_name('.symtab')
		
		desync_list = []
		for symbol in symtab.iter_symbols():
			if 'desyncpoint' in symbol.name:
				desync_list.append(symbol.name)
				print('Appended: {}'.format(symbol.name))
		
		sym_offsets = {}
		for symbol in desync_list:
			syms = symtab.get_symbol_by_name(symbol)
			#We assume there is only one matching symbol
			assert(len(syms) == 1)
			sym = syms[0]
			sym_VA = sym['st_value']
			sym_idx = sym['st_shndx']
			section = elf.get_section(sym_idx)
			section_offset = section['sh_offset']
			section_VA = section['sh_addr']
			sym_offset = sym_VA - section_VA + section_offset
			sym_offsets[symbol] = sym_offset
			print("Offset for symbol [{}]: 0x{:x}".format(symbol, sym_offset))		
		
		for symbol in desync_list:
			
			"""
			For every symbol (desyncpoint) in desync_list, this loop shall:
				
			* Extract a code snippet 
			* Disassembly it and save the length of correctly disassembled bytes
			* Find suitable junk byte(s)
					- Find a random non-single-instruction byte that havent been tried
					  (If len(single_byte_instr) + tried_bytes = 256 => two bytes)
					- Insert the junk bytes into the code snippet
					- Disassemble the code snippet and compare length to original
			* Insert junk byte into file
			"""
			
			"""
			Extract a code snippet of length 100.
			"""
			f.seek(sym_offsets[symbol])
			code = f.read(20)									
						
			"""
			Disassemble the original to and get the length of the disassembled
			bytes.
			"""
			#CODE = b"\xff\xff\xff\xe85\x01\x00\x001\xc0H\x83\xc4\x08\xc3H\x8d=\xda\x01"			
			org_length = get_disasm_length(code)			
			
			"""
			Find suitable junk bytes and insert into file.
			"""			
			desync_length = 0
			pos_bytes = get_pos_bytes_lists()
			while (desync_length != org_length):
				(junk_bytes, pos_bytes) = find_junk_bytes(pos_bytes, [])
				if junk_bytes == -1:
					print("Error! No possible junk bytes")
					break
				else:
					desync_code = insert_junk_bytes(code, junk_bytes)
					desync_length = get_disasm_length(desync_code)
					print("Org_length: {}, Desync_length: {}".format(org_length, desync_length))
				
			
		f.close()
		


if __name__ == '__main__':
	main()
