#!/usr/bin/env python3 

import pefile 
import peutils
import mdutils
import sys
import os
import datetime
import hashlib
import json
import requests

class Analyse: 
	def __init__(self,PATH:str,API):
		self.PATH = PATH
		self.api = API
		if sys.platform in ("linux","linux2"): 
			print("Platform: LINUX") 
			self.PATH_LIST = PATH.split("/") 
			self.FULL_FILE_NAME = self.PATH_LIST[len(self.PATH_LIST)-1]
			self.FILE_NAME = self.FULL_FILE_NAME.split(".")[0]
			self.pe = pefile.PE(PATH)
		elif sys.platform == "win32":
			print("Platform: WINDOWS")
			self.PATH_LIST = PATH.split("\\")
			self.FULL_FILE_NAME =  self.PATH_LIST[len(self.PATH_LIST)-1]
			self.FILE_NAME = self.FULL_FILE_NAME.split(".")[0]
			self.pe = pefile.PE(PATH)
		else: 
			print("Only supported on windows and linux")
			sys.exit(1)
	def	get_path_list(self):
		return self.PATH_LIST
	def get_full_file_name(self):
		return self.FULL_FILE_NAME
	def get_file_name(self):
		return self.FILE_NAME
	def get_hash(self):
		sha256 = hashlib.sha256()
		md5 = hashlib.md5()
		BUF = 70000
		with open(self.PATH,'rb') as f: 
			while True: 
				data = f.read(BUF)
				if not data: 
					break 
				sha256.update(data)
				md5.update(data)
		return "SHA256: {}\nMD5: {}".format(sha256.hexdigest(),md5.hexdigest())
	# def get_strings(self):
	# def isUnpacked(self):
	def virustotal_analyse(self):

	def get_import_sections(self):
		sections = ""
		for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
			sections += entry.dll.decode() + "\n"	
			for imp in entry.imports:
				sections += '\t' + str(hex(imp.address)) + "   " + imp.name.decode() + "\n"
		return sections
	def get_unpack_signatures(self):
		signatures = peutils.SignatureDatabase('UserDB.TXT')
		matches = signatures.match_all(pe, ep_only = True)
		return matches 
	def get_timestamp(self):
		time = datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
		time = time.strftime('%Y-%m-%d %H:%M:%S')
		return time 
	def	banner(self):
		banner = """
File Name: {}
Platform: {}
Path: {}
""".format(self.FULL_FILE_NAME,sys.platform,self.PATH)
		return banner 


