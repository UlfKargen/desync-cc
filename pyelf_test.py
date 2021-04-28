import struct
import sys
import random
from itertools import combinations
from capstone import *
from elftools.elf.elffile import ELFFile



#define ONEBYTE_SYM       x86DisassemblerOneByteOpcodes
#define TWOBYTE_SYM       x86DisassemblerTwoByteOpcodes



def print_disasm_info(instr_list):
	for instr in instr_list:
		print("0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))
	disasm_length = instr_list[-1].address + instr_list[-1].size
	print("Amount of correctly disassemled bytes: {} :)".format(disasm_length))



def get_disasm_length(instr_list):
	if instr_list:
		last_instr = instr_list[-1]
		disasm_length = last_instr.address + last_instr.size		
		return disasm_length		
	else:
		print("Error: No bytes correctly disassembled :(")
	return 0

	
	
def get_disasm_instr_list(code):
	md = Cs(CS_ARCH_X86, CS_MODE_64)	
	instr_list = []
	for i in md.disasm(code, 0x0000):
		instr_list.append(i)
	return instr_list
	
	

def is_desynchronized(org_instr_list, desync_instr_list, num_junk_bytes):
	org_address = org_instr_list[num_junk_bytes].address
	for instr in desync_instr_list:
		if instr.address == org_address:
			return False
		elif instr.address > org_address:
			return True
			
			
	
def insert_junk_bytes(code, junk_bytes):
	"""
	Currently confined to junk_bytes of length one or two.
	"""
	desync_code = bytearray(code)
	
	if len(junk_bytes) == 1:
		desync_code[1] = junk_bytes[0]
	elif len(junk_bytes) == 2:
		desync_code[0] = junk_bytes[0]
		desync_code[1] = junk_bytes[1]
	
	return bytes(desync_code)
	
	
	
def find_junk_bytes(pos_single_bytes, pos_double_bytes):
	"""
	Currently confined to junk_bytes of length one or two.
	"""
	junk_bytes = []	
	if pos_single_bytes:		
		i = random.randrange(len(pos_single_bytes)-1)
		junk_bytes.append(pos_single_bytes.pop(i))
	elif pos_double_bytes:
		i = random.randrange(len(pos_double_bytes)-1) 
		junk_bytes = pos_double_bytes.pop(i)		
	print("Trying junk bytes: {}".format(bytes([junk_bytes[0]])))
	return (junk_bytes, pos_single_bytes, pos_double_bytes)
	
	
	
def get_pos_bytes_lists():
	#from capstone get list of single byters
	#C = list(set(A)) # - set(B))	
	pos_single_bytes = list(range(0, 256))
	pos_double_bytes = list(combinations(pos_single_bytes, 2))
	return (pos_single_bytes, pos_double_bytes)
	
	
def get_desync_list(symtab):
	"""
	Use the symbol table to find all desynchronization symbols.
	Name standard: desyncpoint_[index]_[size]
	"""
	desync_list = []
	for symbol in symtab.iter_symbols():
		if 'desyncpoint' in symbol.name:
			desync_list.append(symbol.name)
			print('Appended: {}'.format(symbol.name))
	"""
	Desyncpoints must be handled in descending order.
	"""
	desync_list.sort(reverse=True)			
	return desync_list
	
	
	
def get_sym_offsets(desync_list, symtab, elf):
	"""
	Get the offsets for each desynchronization point.
	Return: {'desyncpoint', offset}
	"""
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
		#print("Offset for symbol [{}]: 0x{:x}".format(symbol, sym_offset))
	return sym_offsets
	
	

def main():
	
	#!/usr/bin/python3

	binary = sys.argv[1]
	arg_symbol = sys.argv[2]
	NUM_JUNK_BYTES = 2
	READ_LENGTH = 50

	with open(binary, 'r+b') as f:
		elf = ELFFile(f)
		symtab = elf.get_section_by_name('.symtab')
		desync_list = get_desync_list(symtab)
		sym_offsets = get_sym_offsets(desync_list, symtab, elf)			
		
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
			DEBUG PRINT
			"""
			print("\n--------------------")
			print("Desynchronizing point: {}".format(symbol))
			print("--------------------")
			
			"""
			Extract a code snippet of length READ_LENGTH.
			"""			
			#with open(binary, 'rb') as f:
			f.seek(sym_offsets[symbol])
			code = f.read(READ_LENGTH)
			#f.close()								
						
			"""
			Disassemble the original to and get the length of the disassembled
			bytes.
			"""
			org_instr_list = get_disasm_instr_list(code)
			org_length = get_disasm_length(org_instr_list)
			print_disasm_info(org_instr_list)
			
			"""
			Find suitable junk bytes and insert into file.
			"""			
			desync_length = 0
			(pos_single_bytes, pos_double_bytes) = get_pos_bytes_lists()			
			junk_bytes = []
			desynchronized = False			
			while (not desynchronized):
				(junk_bytes, pos_single_bytes, pos_double_bytes) = find_junk_bytes(pos_single_bytes, pos_double_bytes)				
				if junk_bytes:
					desync_code = insert_junk_bytes(code, junk_bytes)
					desync_instr_list = get_disasm_instr_list(desync_code)
					desync_length = get_disasm_length(desync_instr_list)
					print_disasm_info(desync_instr_list)
					print("Org_length: {}, Desync_length: {}".format(org_length, desync_length))
					desynchronized = (desync_length == org_length) and is_desynchronized(org_instr_list, desync_instr_list, NUM_JUNK_BYTES)					
				else:
					print("Achtung! No possible junk bytes.")
					break
			"""
			Write the changes to the file.			
			"""						
			i = 1		
			for junk_byte in reversed(junk_bytes):
				f.seek(sym_offsets[symbol]+NUM_JUNK_BYTES-i)
				f.write(bytes([junk_byte]))		
				i += 1		
				
	f.close()
									
		


if __name__ == '__main__':
	main()
