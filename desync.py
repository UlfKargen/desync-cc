import argparse
import sys



def create_predicate(num):
	strnum = str(num)
	junk_bytes = '\t.byte\t0x00\n\t.byte\t0x00\n\t.byte\t0x00\n'
	return '\txorl\t%eax,\t%eax\n\tcmpl\t%eax,\t%eax\n\tje\t.LFOO'\
			+ strnum + '\ndesyncpoint' \
			+ strnum + ':\n' + junk_bytes + '.LFOO' + strnum + ':\n'
	
	

def main():
	"""
	Retrieve filename as an argument from the terminal
	"""
	print("Starting main...\n")
	parser = argparse.ArgumentParser(description = 'filenames')
	parser.add_argument('filenames', nargs = '+', type = str)
	args = parser.parse_args()
	filenames = args.filenames
	print(filenames)	
	"""
	Try to open the file. If a file with the name 'new_file.S' already
	exists, an error is raised.
	"""
	
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
				Insert the predicate.
				"""							
				file_string += create_predicate(desync_count)
				symbol_string += "\t.globl\tdesyncpoint" + str(desync_count) + "\n"
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
