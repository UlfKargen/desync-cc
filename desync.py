import argparse
import sys
import random


def create_predicate(desync_count, num_junk_bytes, junk_bytes):
	strnum = str(desync_count)	
	junk_strnum = str(num_junk_bytes)
	return '\txorl\t%eax,\t%eax\n\tcmpl\t%eax,\t%eax\n\tje\t.LFOO' \
			+ strnum + '\ndesyncpoint' + strnum + '_' + junk_strnum \
			+ ':\n' + junk_bytes + '.LFOO' + strnum + ':\n'
	
	
	
def create_junk_bytes(num_junk_bytes, single_byte_instr_list):
	junk_bytes = ''
	for i in range(num_junk_bytes):
		junk_bytes += '\t.byte\t' +  random.choice(single_byte_instr_list) + '\n'
	
	return junk_bytes	



def create_single_byte_instr_list():
	single_byte_instr_list = []
	single_byte_instr_list.append('0x90')
	
	return single_byte_instr_list


def main():
	"""
	Retrieve filename as an argument from the terminal
	"""
	print("Starting main...\n")
	parser = argparse.ArgumentParser(description = 'filenames')
	parser.add_argument('filenames', nargs = '+', type = str)
	
	parser.add_argument("-f", "--fixed", type=int,
                    help="Set the amount of junk bytes to a fixed number")
	args = parser.parse_args()
	filenames = args.filenames
	print(filenames)	
	
	"""
	Try to open the file. If a file with the name 'new_file.S' already
	exists, an error is raised.
	"""	
	single_byte_instr_list = create_single_byte_instr_list()
	for filename in filenames:
		f = open(filename, 'r+')
		
		desync_count = 0
		symbol_string = ".LCDESYNC:\n"
		file_string = ""
		index = -1	
		
		nextline = f.readline()
		while nextline:
			if (nextline.find('call') != -1):			
				"""
				Create junk byte sequence and insert the predicate.
				"""		
				num_junk_bytes = 0
				if args.fixed:
					num_junk_bytes = args.fixed
				else:
					num_junk_bytes = random.randint(1, 3)				
				junk_bytes = create_junk_bytes(num_junk_bytes, single_byte_instr_list)				
				
				file_string += create_predicate(desync_count, num_junk_bytes, junk_bytes)
				symbol_string += "\t.globl\tdesyncpoint" + str(desync_count) + "_" + str(num_junk_bytes) + "\n"
				desync_count += 1
			elif nextline.find('main:') != -1:
				"""
				Save the index where we are supposed to insert the global 
				symbols.
				"""
				index = len(file_string)		
			file_string += nextline
			nextline = f.readline()
		
		"""
		Depending on whether or not any desync points have been inserted,
		the symbol declarations must be inserted before it can be written
		to a new file.
		"""
		if index >= 0:
			write_file = file_string[:index] + symbol_string + file_string[index:]
		else:
			write_file = file_string				
#		f.read()
		f.seek(0)
		f.write(write_file)
		f.truncate()
		
		"""
		Close the file.
		"""
		f.close()		
	
	print("Main finished!")
	
	

if __name__ == "__main__":
	main()
