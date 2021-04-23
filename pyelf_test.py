import struct
import sys
from capstone import *
from elftools.elf.elffile import ELFFile


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
			f.seek(sym_offsets[symbol])
			temp = f.read(20)
			#junk_byte = b'\xAA'
			#temp[2] = 170
			#temp = temp[:2]+ junk_byte + temp[2+1:]			
			print('En slice: \n{}'.format(temp))
						
			"""
			Disassemble the slice and print the resulting instructions
			"""
			CODE = b"\xe85\x01\x00\x001\xc0H\x83\xc4\x08\xc3H\x8d=\xda\x01"
			
			md = Cs(CS_ARCH_X86, CS_MODE_64)
			for i in md.disasm(CODE, 0x1000):
				print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))				
			
		f.close()
		
		
	"""
	FILE = 'test_desync'

	elf = ELFFile(open(FILE, 'rb'))

	symtab = elf.get_section_by_name('.symtab')
	if not symtab:
		print('No symbol table available')
		sys.exit(1)

	name = 'desyncpoint0'
	sym_count = 0
	NAMELEN = 12
	sym_list = symtab.get_symbol_by_name(name)
	while sym_list:
		print('Symbol {}: {} \n'.format(sym_count, symtab.get_section_index(sym_list[0])))
		
		#Gör lite saker...
				
		sym_count += 1
		name = name[:NAMELEN-1] + str(sym_count)
		sym_list = symtab.get_symbol_by_name(name)
	
"""


if __name__ == '__main__':
	main()
