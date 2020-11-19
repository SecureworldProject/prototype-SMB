import psutil
import os

import time
from datetime import datetime

def getBrowserList():
	chromes=[]
	pids=psutil.process_iter()
	for p in pids:
		name=str(p.name)
		if (name.find("chrome.exe")>=0):
			chromes.append(p) # fichamos a chrome
	return chromes
##############################################################	

def exploraFiles( file,chromes=[]):
	encontrado=False
	for p in chromes:
		try:
			of= p.open_files()
			for i in of:
				if (i.path.find(file)>=0):
					print ("encontrado :" ,i)
					entontrado=True
		except:
			# if you kill a browser during this exploration
			print ("excepcion")
			continue
	return encontrado
##############################################################	
chromes=[]

print ("ENTRAMOS EN BUCLE")
#print ("hay ", len(chromes) ," chromes abiertos")
now = datetime.now()
t1 = datetime.timestamp(now)
print("t1 =", t1)

while (True):
	print("------ sleep... -------")
	time.sleep(2)
	print("------ checking... -------")
	now = datetime.now()
	t1 = datetime.timestamp(now)
	print("t1 =", t1)
	chromes=getBrowserList()
	now = datetime.now()
	t2 = datetime.timestamp(now)
	print("t list=", t2-t1)
	print ("hay ", len(chromes) ," chromes abiertos")
	now = datetime.now()
	t1 = datetime.timestamp(now)
	
	for p in chromes:
		try:
			of= p.open_files()
			for i in of:
				#print (i)
				if (i.path.find(".mp4")>=0):
					print (i)
		except:
			# if you kill a browser during this exploration
			print ("excepcion")
			continue
	now = datetime.now()
	t2 = datetime.timestamp(now)
	print("t files=", t2-t1)
	

