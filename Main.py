from Analyse import * 
import os 

PATH = input("Path of EXE: ")
assert os.path.exists(PATH), "File does not exits\n Path given: "+str(PATH)
api = open("./API","r")  
if api.read() == "" :
	print("Enter Virus total API key in ./API")
	exit(1)
API = api.read()  
anl = Analyse(PATH,API)
print(anl.banner())
print("Analysis started")

md = mdutils.MdUtils(file_name=anl.get_file_name()) 

md.new_header(level=1, title='REPORT')
md.new_header(level=2, title='Static analysis')

print(f"Timestamp: {anl.get_timestamp()}")


print("Analysing import sections")
md.new_header(level=3, title='Import Sections')
md.insert_code(anl.get_import_sections())

print("done !!!")
md.create_md_file()

"""
TODO

Add virus total 
add option to see if a file is packed or not 
add strings
"""
