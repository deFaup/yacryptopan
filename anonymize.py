# /bin/bash python3
# key generation
# date +%s | sha256sum | base64 | head -c 32 ; echo

"""
  Anonymize a file of IPv4 strings using CryptoPAn.

  Args:
      input:
        filename: PATH to the IP file
      optional: 
        "print": to print the IP and its conversion
      output:
        file: "anonymized_IP.csv" with anonymized IPs
        file: "unique_real_IP.csv" with real IPs
        file: "frequecies.csv" with the frequency of each IP
        all file are a one to one mapping and reflect the same IP
"""

import sys, os
from yacryptopan import CryptoPAn

if len(sys.argv) < 2:
  print("missing IP file")
  quit()

printBool = 0
if len(sys.argv) == 3 and sys.argv[2]=="print":
  printBool = 1

# Create a 32 bytes key for CryptoPAn
  # used for AES key and padding when performing a block cipher operation. 
  # The first 16 bytes are used for the AES key, and the latter for padding.
os.system("date +%s | sha256sum | base64 | head -c 32 > anonymization_key")  
keyFile = open("anonymization_key")
key = keyFile.read(32) #read the first 32 bytes (which are the only bytes)
keyFile.close()
os.remove("anonymization_key")
byteKey = bytes(key,'utf-8')
print("key:", byteKey, '\n')
cp = CryptoPAn(byteKey)


#1.Open the IP file
#2.Parse the IP file
inputFile = open(sys.argv[1], "r")            #read
anonFile = open("anonymized_IP.csv","w")      #write
uniqueFile = open("unique_real_IP.csv","w")   #write
frequenciesFile = open("frequecies.csv", "w")

uniqueRealIPMap = {}

ip = inputFile.readline()
while ip != '':

  if(ip not in uniqueRealIPMap):    #only take unique IPs from the input file
    uniqueRealIPMap[ip]=1
    ip = inputFile.readline()

  else:
    uniqueRealIPMap[ip]+=1

for ip_ in iter(uniqueRealIPMap):
  uniqueFile.write(ip_)     #add real IP to unique_real_IP file
  
  ip=ip_
  ip = list(ip)             #convert the line from string to list
  ip.pop()                  #remove '\n'
  ip = ''.join(ip)          #put the list back into a string
  anonymized_ip = cp.anonymize(ip)      #anonymize the IP
  anonFile.write(anonymized_ip + '\n')  #add it to anonymized_IP file

  frequenciesFile.write(str(uniqueRealIPMap[ip_])+'\n') #write frequency

  if printBool:
    print("ip:",ip)
  if printBool:
    print("anon_ip:",anonymized_ip, '\n')

inputFile.close()
anonFile.close()
uniqueFile.close()
frequenciesFile.close()