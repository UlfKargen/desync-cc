import argparse
import random
import math
import datetime
from itertools import combinations
from capstone import *
from elftools.elf.elffile import ELFFile

"""
Global boolean used for enabling debug info.
"""
PRINT_DEBUG_INFO = False
PRINT_BENCHMARK_INFO = False


def print_disasm_info(instr_list):
	"""
	Prints the instructions in readable format. Used for debugging.
	"""
	if instr_list:
		for instr in instr_list:
			print('0x%x:\t%s\t%s' %(instr.address, instr.mnemonic, instr.op_str))
		disasm_length = instr_list[-1].address + instr_list[-1].size				
		print('Amount of correctly disassembled bytes: {} :)'.format(disasm_length))
	else:
		print('Instruction list is empty :(')



def get_disasm_length(instr_list):
	"""
	Return the length of the disassembled code, measured in bytes.
	"""
	disasm_length = 0
	if instr_list:
		last_instr = instr_list[-1]
		disasm_length = last_instr.address + last_instr.size		
	else:
		if PRINT_DEBUG_INFO:
			print('Error: No bytes correctly disassembled :(')		
	return disasm_length		

	
	
def get_disasm_instr_list(code):
	"""
	Uses Capstone to disassemble the given code snippet and returns
	a list with the resulting instructions.
	"""
	md = Cs(CS_ARCH_X86, CS_MODE_64)	
	instr_list = []
	for i in md.disasm(code, 0x0000):
		instr_list.append(i)
	return instr_list
	
	

def is_desynchronized(org_instr_list, desync_instr_list, num_junk_bytes):
	"""
	Checks if there is an instruction at the immediate position after
	junk bytes. If so, the file have not been desynchronized.
	"""
	org_address = org_instr_list[num_junk_bytes].address
	for instr in desync_instr_list:
		if instr.address == org_address:
			return False
		elif instr.address > org_address:
			return True
			
			
	
def insert_junk_bytes(code, junk_bytes, len_junk_bytes):
	"""
	Insert the junk bytes into the correct position, i.e. at the end of
	the junk byte slots. The code snippet begins at the first junk byte
	slot.
	"""
	desync_code = bytearray(code)
	index = len_junk_bytes - len(junk_bytes)
	for i in range(len(junk_bytes)):		
		desync_code[index + i] = junk_bytes[i]			
	
	return bytes(desync_code)
	
	
	
def find_junk_bytes(pos_single_bytes, len_junk_bytes):
	"""
	Chooses a random byte segment of the given length, starting with the
	most. Return [] if no more options.
	"""
	junk_bytes = []	
	
	if len_junk_bytes > 1:
		for i in range(len_junk_bytes):
			if i == 0:
				junk_bytes.append(random.choice(pos_single_bytes))
			else:
				junk_bytes.append(random.randint(0, 255))
				
	elif pos_single_bytes:				
		junk_bytes.append(pos_single_bytes.pop(-1))
	
	return (junk_bytes, pos_single_bytes, len_junk_bytes)
	
	
	
def get_pos_single_bytes_list(instr_file_dir):	
	"""
	Create a list with possible starting junk bytes. Single bytes that 
	work as instructions and prefixes have been removed.
	"""
	pos_single_bytes = random.sample(range(256), 256)
	single_byte_instr_list = []
	instr_prefix_list = []
	with open(instr_file_dir + '/single_byte_instr_list.txt', 'r') as f:
		byte = f.readline()
		while byte:
			byte = byte[:-1]
			single_byte_instr_list.append(int(byte[2:], 16)) #Cut away the newline
			byte = f.readline()
		f.close()	
	with open(instr_file_dir + '/instr_prefix_list.txt', 'r') as f:
		prefix = f.readline()
		while prefix:
			prefix = prefix[:-1]
			instr_prefix_list.append(int(prefix[2:], 16))
			prefix = f.readline()
		f.close()
	
	"""
	Removes the single byte instructions and prefixes.
	"""	
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
			if PRINT_DEBUG_INFO:
				print('Appended: {}'.format(symbol.name))
	"""
	Desyncpoints must be handled in descending order.
	"""
	desync_list.sort(key = lambda x: x[:-2], reverse=True)			
	return desync_list
	
	
	
def get_sym_offsets(desync_list, symtab, elf):
	"""
	Get the offsets for each desynchronization point.
	Return: {'desyncpoint', offset}
	"""
	sym_offsets = {}
	for symbol in desync_list:
		syms = symtab.get_symbol_by_name(symbol)		
		assert(len(syms) == 1)
		sym = syms[0]
		sym_VA = sym['st_value']
		sym_idx = sym['st_shndx']
		section = elf.get_section(sym_idx)
		section_offset = section['sh_offset']
		section_VA = section['sh_addr']
		sym_offset = sym_VA - section_VA + section_offset
		sym_offsets[symbol] = sym_offset	
		if PRINT_DEBUG_INFO:
			print('Offset for symbol [{}]: 0x{:x}'.format(symbol, sym_offset))
	return sym_offsets
	
		
		
def main():
	"""
	Used for benchmark: Start of main()
	"""
	main_start_time = datetime.datetime.now()
	
	
	"""
	Retrieve the arguments, namely the name of the binary that is to be
	desynchronized, and a flag -v (--verbose) used for debugging info.
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('binary', type = str)
	parser.add_argument('instr_file_dir', type = str)
	parser.add_argument('-v', '--verbose', action = 'store_true',
                    help='Enable debug print information')
	args = parser.parse_args()
	binary = args.binary
	instr_file_dir = args.instr_file_dir
	if args.verbose:
		PRINT_DEBUG_INFO = True
	else:
		PRINT_DEBUG_INFO = False
	
	"""
	Constants used in the main loop
	"""
	TRIES = 1000
	READ_LENGTH = 50
	
	"""
	Benchmark variables.
	"""
	desynced = 0
	undesynced = 0
	
	max_symbol_loop_time = 0
	min_symbol_loop_time = math.inf
	total_symbol_loop_time = 0
	
	max_symbol_loops = 0
	min_symbol_loops = math.inf
	total_symbol_loops = 0

	with open(binary, 'r+b') as f:
		elf = ELFFile(f)
		symtab = elf.get_section_by_name('.symtab')
		desync_list = get_desync_list(symtab)
		sym_offsets = get_sym_offsets(desync_list, symtab, elf)			
		
		for symbol in desync_list:			
			"""
			Used for benchmark: Start of symbol loop
			"""
			start_time = datetime.datetime.now()
			loop_count = 0
			
			"""
			Extract a code snippet of length READ_LENGTH.
			"""			
			f.seek(sym_offsets[symbol])
			code = f.read(READ_LENGTH)									
						
			"""
			Disassemble the original to and get the length of the disassembled
			bytes.
			"""
			org_instr_list = get_disasm_instr_list(code)
			org_length = get_disasm_length(org_instr_list)
						
			if PRINT_DEBUG_INFO:				
				print('\n-------------------------------------')
				print('Desynchronizing point: {}'.format(symbol))
				print('-------------------------------------')
				print('--- Original Assembly Code ---')
				print_disasm_info(org_instr_list)
				print('\n')
				
							
			"""
			Find suitable junk bytes and insert into file.
			"""			
			desync_length = 0
			pos_single_bytes = get_pos_single_bytes_list(instr_file_dir)
			junk_bytes = []
			JUNK_BYTE_SLOTS = int(symbol[-1]) #last character in symbol name
			len_junk_bytes_tried = JUNK_BYTE_SLOTS
			tries_left = TRIES
			desynchronized = False			
			while (not desynchronized):
				loop_count += 1
				if tries_left == 0:
					tries_left = TRIES
					len_junk_bytes_tried -= 1					
				(junk_bytes, pos_single_bytes, len_junk_bytes_tried) = find_junk_bytes(pos_single_bytes, len_junk_bytes_tried)
				tries_left -= 1
				
				if junk_bytes:
					desync_code = insert_junk_bytes(code, junk_bytes, JUNK_BYTE_SLOTS)
					desync_instr_list = get_disasm_instr_list(desync_code)
					desync_length = get_disasm_length(desync_instr_list)
					
					if PRINT_DEBUG_INFO:						
						junk_print = ''
						for junk_byte in junk_bytes:
							junk_print += str(bytes([junk_byte]))		
						print('Trying to desynchronize with junk bytes: ' + junk_print)
						print('--- Desynchronized Code ---')
						print_disasm_info(desync_instr_list)													
						print('\n--- Org_length: {} ---'.format(org_length))
						print('--- Desync_length: {} ---\n'.format(desync_length))						
					
					desynchronized = (desync_length == org_length) and is_desynchronized(org_instr_list, desync_instr_list, JUNK_BYTE_SLOTS)					
				else:					
					break
			
			"""
			Write the changes to the file.			
			"""
			if junk_bytes:
				desynced += 1
				if PRINT_DEBUG_INFO:
					print('**********\n Success for symbol {} \n**********\n'.format(symbol))				
				i = 1		
				for junk_byte in reversed(junk_bytes):
					f.seek(sym_offsets[symbol]+JUNK_BYTE_SLOTS-i)
					f.write(bytes([junk_byte]))		
					i += 1
			else:
				undesynced += 1
				if PRINT_DEBUG_INFO:
					print('**********\n Failure for symbol {} \n ********** '.format(symbol))
					print('No suitable junk bytes found')

			if PRINT_BENCHMARK_INFO:				
				end_time = datetime.datetime.now() 
				exec_time = (end_time - start_time).microseconds / 1000
				
				if exec_time > max_symbol_loop_time:
					max_symbol_loop_time = exec_time
				if exec_time < min_symbol_loop_time:	
					min_symbol_loop_time = exec_time
				total_symbol_loop_time += exec_time					
				
				if loop_count > max_symbol_loops:
					max_symbol_loops = loop_count
				if loop_count < min_symbol_loops:
					min_symbol_loops = loop_count
				total_symbol_loops += loop_count
			
			if PRINT_DEBUG_INFO:
				print('--- Execution time for desynchronization: {}---'.format(exec_time))
				print('--- Loops needed: {} ---\n'.format(loop_count))
			
		f.close()
	
	"""
	Used for benchmark: End of main()
	"""
	main_end_time = datetime.datetime.now()
	main_exec_time = (main_end_time - main_start_time).seconds

	
	if PRINT_BENCHMARK_INFO:
		print('\n--- BENCHMARK RESULTS ---\n')
		
		print('Number of successful desynchronizations: {}'.format(desynced))
		print('Number of unsuccessful desynchronizations: {}\n'.format(undesynced))
		
		print('Total execution time (s): {}\n'.format(main_exec_time))
		
		print('Maximum desynchronization loop time (ms): {}'.format(max_symbol_loop_time))
		print('Minimum desynchronization loop time (ms): {}'.format(min_symbol_loop_time))
		print('Average desynchronization loop time (ms): {:.3f}\n'.format(total_symbol_loop_time / len(desync_list)))
		
		print('Maximum amount of loops needed to desynchronize: {}'.format(max_symbol_loops))
		print('Minimum amount of loops needed to desynchronize: {}'.format(min_symbol_loops))
		print('Average amount of loops needed to desynchronize: {:.3f}\n'.format(total_symbol_loops / len(desync_list)))

if __name__ == '__main__':
	main()
