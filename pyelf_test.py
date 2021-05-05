import struct
import sys
import random
from itertools import combinations
from capstone import *
from elftools.elf.elffile import ELFFile



#define ONEBYTE_SYM       x86DisassemblerOneByteOpcodes
#define TWOBYTE_SYM       x86DisassemblerTwoByteOpcodes



def print_disasm_info(instr_list):
	if instr_list:
		for instr in instr_list:
			print("0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))
		disasm_length = instr_list[-1].address + instr_list[-1].size
		print("Amount of correctly disassembled bytes: {} :)".format(disasm_length))
	else:
		print("Instruction list is empty :(")



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
			
			
	
def insert_junk_bytes(code, junk_bytes, len_junk_bytes):
	"""
	Now its perfect in every concievable scenario in the universe and beyond.
	"""
	desync_code = bytearray(code)
	
	index = len_junk_bytes - len(junk_bytes)
	for i in range(len(junk_bytes)):		
		desync_code[index + i] = junk_bytes[i]			
	
	return bytes(desync_code)
	
	
	
def find_junk_bytes(pos_single_bytes, len_junk_bytes):
	"""
	Chooses a random byte segment of the given length, starting with the
	largest possible. Return [] if no more options.
	"""
	#Random choice
	junk_bytes = []	
	
	if len_junk_bytes > 1:
		for i in range(len_junk_bytes):
			if i == 0:
				junk_bytes.append(random.choice(pos_single_bytes))
			else:
				junk_bytes.append(random.randint(0, 255))
				
	elif pos_single_bytes:				
		junk_bytes.append(pos_single_bytes.pop(-1))
	
	if junk_bytes:
		junk_print = ''
		for junk_byte in junk_bytes:
			junk_print += str(bytes([junk_byte]))
		print("Trying junk bytes: " + junk_print)

	return (junk_bytes, pos_single_bytes, len_junk_bytes)
	
	
	
def get_pos_bytes_lists():	
	pos_single_bytes = random.sample(range(256), 256)
	single_byte_instr_list = []
	instr_prefix_list = []
	with open('single_byte_instr_list.txt', 'r') as f:
		byte = f.readline()
		while byte:
			byte = byte[:-1]
			single_byte_instr_list.append(int(byte[2:], 16)) #Cut away the newline
			byte = f.readline()
		f.close()	
	with open('instr_prefix_list.txt', 'r') as f:
		prefix = f.readline()
		while prefix:
			prefix = prefix[:-1]
			instr_prefix_list.append(int(prefix[2:], 16))
			prefix = f.readline()
		f.close()
		
	pos_single_bytes = list(set(pos_single_bytes) - set(single_byte_instr_list + instr_prefix_list))
	return pos_single_bytes
	
	
	
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
	#NUM_JUNK_BYTES = 2
	TRIES = 1000
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
			code = f.read(READ_LENGTH) #Kolla slutet
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
			pos_single_bytes = get_pos_bytes_lists()
			junk_bytes = []
			JUNK_BYTE_SLOTS = int(symbol[-1])
			len_junk_bytes_tried = JUNK_BYTE_SLOTS
			tries_left = TRIES
			desynchronized = False			
			while (not desynchronized):
				if tries_left == 0:
					tries_left = TRIES
					len_junk_bytes_tried -= 1
					print("Decrementing tries")
				(junk_bytes, pos_single_bytes, len_junk_bytes_tried) = find_junk_bytes(pos_single_bytes, len_junk_bytes_tried)
				tries_left -= 1
				
				if junk_bytes:
					desync_code = insert_junk_bytes(code, junk_bytes, JUNK_BYTE_SLOTS)
					desync_instr_list = get_disasm_instr_list(desync_code)
					desync_length = get_disasm_length(desync_instr_list)
					print_disasm_info(desync_instr_list)
					print("Org_length: {}, Desync_length: {}".format(org_length, desync_length))
					desynchronized = (desync_length == org_length) and is_desynchronized(org_instr_list, desync_instr_list, JUNK_BYTE_SLOTS)					
				else:
					print("Achtung! No possible junk bytes.")
					break
			"""
			Write the changes to the file.			
			"""						
			i = 1		
			for junk_byte in reversed(junk_bytes):
				f.seek(sym_offsets[symbol]+JUNK_BYTE_SLOTS-i)
				f.write(bytes([junk_byte]))		
				i += 1		
				
	f.close()
									
		


if __name__ == '__main__':
	main()
