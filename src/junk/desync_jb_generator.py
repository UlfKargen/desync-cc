#!/usr/bin/env python3

import argparse
import random
import math
import datetime
import os
from capstone import *
from elftools.elf.elffile import ELFFile

DEFAULT_FAKE_JUMP_INTERVAL = 5

INSTR_PREFIX_LIST = [
	0x26,
	0x2E,
	0x36,
	0x3E,
	0x40,
	0x41,
	0x42,
	0x43,
	0x44,
	0x45,
	0x46,
	0x47,
	0x48,
	0x49,
	0x4A,
	0x4B,
	0x4C,
	0x4D,
	0x4E,
	0x4F,
	0x64,
	0x65,
	0x66,
	0x67,
	0x9B,
	0xF0,
	0xF2,
	0xF3
]

SINGLE_BYTE_INSTR_LIST = [
	0x50,
	0x58,
	0x98,
	0x99,
	0x9D,
	0x9F,
	0x9B,
	0x9C,
	0x9E,
	0xC3,
	0xCB,
	0xD7,
	0xF4,
	0xF5,
	0xF8,
	0xF9,
	0xFA,
	0xFB,
	0xFC,
	0xFD
]

ALL_POS_SINGLE_BYTES = list(set(range(256)) - set(SINGLE_BYTE_INSTR_LIST + INSTR_PREFIX_LIST))

class DesyncPoint:
	def __init__(self, index, size, offset):
		self.index = index
		self.size = size
		self.offset = offset

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



def get_disasm_length(instr_list, verbose=False):
	"""
	Return the length of the disassembled code, measured in bytes.
	"""
	disasm_length = 0
	if instr_list:
		last_instr = instr_list[-1]
		disasm_length = last_instr.address + last_instr.size		
	else:
		if verbose:
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
	

	
def get_possible_fake_targets(instr_list, max_junk_size):
	"""
	Returns a list of possible jump targets for fake (never taken) branches,
	such that the jump will result in a desynchronization
	"""
	result = []
	for instr in instr_list:
		for i in range(1, instr.size):
			offset = instr.address + i
			if offset >= max_junk_size:
				return result
			result.append(offset)
	return result



def is_desynchronized(desync_instr_list, num_junk_bytes):
	"""
	Checks if there is an instruction at the immediate position after
	junk bytes. If so, the file have not been desynchronized.
	"""
	for instr in desync_instr_list:
		if instr.address == num_junk_bytes:
			return False
		elif instr.address > num_junk_bytes:
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
	
	return (junk_bytes, pos_single_bytes)
	


def get_desync_list(symtab, elf, verbose=False):
	"""
	Use the symbol table to find all desynchronization symbols.
	Name standard: desyncpoint_[index]_[size]
	"""
	desync_list = []
	max_junk_size = 0
	for symbol in symtab.iter_symbols():
		if 'desyncpoint' in symbol.name:
			(_, index, size) = symbol.name.split('_')
			max_junk_size = max(max_junk_size, int(size))

			sym_VA = symbol.entry['st_value']
			sym_idx = symbol.entry['st_shndx']
			section = elf.get_section(sym_idx)
			section_offset = section['sh_offset']
			section_VA = section['sh_addr']
			offset = sym_VA - section_VA + section_offset

			desync_list.append(DesyncPoint(int(index), int(size), offset))

			if verbose:
				print('Appended: {}'.format(symbol.name))
	"""
	Desyncpoints must be handled in descending order.
	"""
	desync_list.sort(key = lambda x: x.index, reverse=True)		
	return (desync_list, max_junk_size)
	
	
		
def main():
	"""
	Used for benchmark: Start of main()
	"""
	main_start_time = datetime.datetime.now()
	
	PRINT_DEBUG_INFO = bool(os.getenv("DESYNC_JUNK_DEBUG"))
	PRINT_BENCHMARK_INFO = bool(os.getenv("DESYNC_JUNK_BENCHMARK"))

	"""
	Retrieve the arguments, namely the name of the binary that is to be
	desynchronized, and a flag -v (--verbose) used for debugging info.
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('binary', type = str)
	parser.add_argument('-v', '--verbose', action = 'store_true',
                    help='Enable debug print information')
	args = parser.parse_args()
	binary = args.binary
	if args.verbose:
		PRINT_DEBUG_INFO = True
	
	"""
	Constants used in the main loop
	"""
	TRIES = 1000
	READ_LENGTH = 50
	
	"""
	Benchmark variables.
	"""
	desynced_always = 0
	undesynced_always = 0

	desynced_never = 0
	failed_valid_never = 0
	failed_invalid_never = 0
	
	max_symbol_loop_time = 0
	min_symbol_loop_time = math.inf
	total_symbol_loop_time = 0
	
	max_symbol_loops = 0
	min_symbol_loops = math.inf
	total_symbol_loops = 0

	with open(binary, 'r+b') as f:
		elf = ELFFile(f)
		symtab = elf.get_section_by_name('.symtab')
		desync_list, max_junk_size = get_desync_list(symtab, elf, PRINT_DEBUG_INFO)
		if max_junk_size < 2:
			# Too few instructions to perfrom a desynchronizing jump
			max_junk_size = DEFAULT_FAKE_JUMP_INTERVAL
		assert max_junk_size < 128
		
		for symbol in desync_list:			
			"""
			Used for benchmark: Start of symbol loop
			"""
			start_time = datetime.datetime.now()
			loop_count = 0
			
			"""
			Extract a code snippet of length READ_LENGTH.
			"""			
			f.seek(symbol.offset)
			code = f.read(READ_LENGTH)									
						
			"""
			Disassemble the original to and get the length of the disassembled
			bytes.
			"""
			org_instr_list = get_disasm_instr_list(code)
			org_length = get_disasm_length(org_instr_list, PRINT_DEBUG_INFO)	
						
			if PRINT_DEBUG_INFO:				
				print('\n-------------------------------------')
				print('Desynchronizing point # {}'.format(symbol.index))
				print('-------------------------------------')
				print('--- Original Assembly Code ---')
				print_disasm_info(org_instr_list)
				print('\n')
				
			if not symbol.size:
				"""
				Find suitable target for fake branch, and insert into file
				"""
				if PRINT_DEBUG_INFO:
					print('*** Desynch point type: NEVER TAKEN ***\n')

				possible_jump_targets = get_possible_fake_targets(org_instr_list, max_junk_size)
				random.shuffle(possible_jump_targets)
				for target in possible_jump_targets:
					desync_instr_list = get_disasm_instr_list(code[target:])
					desync_length = get_disasm_length(desync_instr_list)
					if desync_length >= org_length - target:
						desynced_never += 1
						if PRINT_DEBUG_INFO:
							print('Found desynchronizing jump offset: {}\n'.format(target))
							print('--- Desynchronized Code ---')
							print_disasm_info(desync_instr_list)
						break
				else:
					# Failed to find a jump target that gives valid desynchronized assembly.
					# Try to pick a target that at least results in valid (non-desynchronized) code.
					if PRINT_DEBUG_INFO:
						print('No desynchronizing jump offset found...', end = '')

					jump_targets = [i for i in range(1, max_junk_size) if i not in possible_jump_targets]
					if not jump_targets:
						# Not possible to find valid targets, just pick a random target
						failed_invalid_never += 1
						if PRINT_DEBUG_INFO:
							print('and no valid offset found...', end = '')
						jump_targets = range(1, max_junk_size)
					else:
						failed_valid_never += 1
					target = random.sample(jump_targets, 1)[0]
					if PRINT_DEBUG_INFO:
						print('picked offset {}'.format(target))

				f.seek(symbol.offset - 1)
				f.write(bytes([target]))
			else:
				"""
				Find suitable junk bytes and insert into file.
				"""

				if PRINT_DEBUG_INFO:
					print('*** Desynch point type: ALWAYS TAKEN ***\n')

				desync_length = 0
				junk_bytes = []
				junk_bytes_size = symbol.size
				len_junk_bytes_tried = junk_bytes_size
				pos_single_bytes = ALL_POS_SINGLE_BYTES.copy()
				tries_left = TRIES
				desynchronized = False			
				while (not desynchronized):
					loop_count += 1
					if tries_left == 0:
						tries_left = TRIES
						len_junk_bytes_tried -= 1					
					(junk_bytes, pos_single_bytes) = find_junk_bytes(pos_single_bytes, len_junk_bytes_tried)
					tries_left -= 1
					
					if junk_bytes:
						desync_code = insert_junk_bytes(code, junk_bytes, junk_bytes_size)
						desync_instr_list = get_disasm_instr_list(desync_code)
						desync_length = get_disasm_length(desync_instr_list)
						
						if PRINT_DEBUG_INFO:						
							junk_print = ''
							for junk_byte in junk_bytes:
								junk_print += bytes([junk_byte]).hex()
							print('Trying to desynchronize with junk bytes: ' + junk_print)
							print('--- Desynchronized Code ---')
							print_disasm_info(desync_instr_list)													
							print('\n--- Org_length: {} ---'.format(org_length))
							print('--- Desync_length: {} ---\n'.format(desync_length))						
						
						desynchronized = (desync_length >= org_length) and is_desynchronized(desync_instr_list, junk_bytes_size)					
					else:					
						break
				
				"""
				Write the changes to the file.			
				"""
				if junk_bytes:
					desynced_always += 1
					if PRINT_DEBUG_INFO:
						print('**********\n Success for symbol # {} \n**********\n'.format(symbol.index))				
					f.seek(symbol.offset)
					f.write(bytes(junk_bytes))
				else:
					undesynced_always += 1
					if PRINT_DEBUG_INFO:
						print('**********\n Failure for symbol # {} \n************'.format(symbol.index))
						print('No suitable junk bytes found\n')

			if PRINT_BENCHMARK_INFO:				
				end_time = datetime.datetime.now() 
				exec_time = (end_time - start_time).total_seconds() * 1000
				
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
			
			if PRINT_BENCHMARK_INFO and PRINT_DEBUG_INFO:
				print('--- Execution time for desynchronization: {}---'.format(exec_time))
				print('--- Loops needed: {} ---\n'.format(loop_count))
	
	"""
	Used for benchmark: End of main()
	"""
	main_end_time = datetime.datetime.now()
	main_exec_time = (main_end_time - main_start_time).total_seconds()

	
	if PRINT_BENCHMARK_INFO:
		print('\n--- BENCHMARK RESULTS ---\n')
		
		print('Total execution time (s): {}\n'.format(main_exec_time))

		print('--- Always taken branches ---\n')

		print('Number of successful desynchronizations: {}'.format(desynced_always))
		print('Number of unsuccessful desynchronizations: {}\n'.format(undesynced_always))
		
		print('Maximum desynchronization loop time (ms): {}'.format(max_symbol_loop_time))
		print('Minimum desynchronization loop time (ms): {}'.format(min_symbol_loop_time))
		if desync_list:
			print('Average desynchronization loop time (ms): {:.3f}\n'.format(total_symbol_loop_time / len(desync_list)))
		
		print('Maximum amount of loops needed to desynchronize: {}'.format(max_symbol_loops))
		print('Minimum amount of loops needed to desynchronize: {}'.format(min_symbol_loops))
		if desync_list:
			print('Average amount of loops needed to desynchronize: {:.3f}\n'.format(total_symbol_loops / len(desync_list)))

		print('--- Never taken branches ---\n')

		print('Number of successful desynchronizations: {}'.format(desynced_never))
		print('Number of unsuccessful desynchronizations with valid disassembly: {}'.format(failed_valid_never))
		print('Number of unsuccessful desynchronizations with invalid disassembly: {}\n'.format(failed_invalid_never))

if __name__ == '__main__':
	main()
