from shodan import Shodan
from datetime import datetime
from operator import itemgetter
import ipinfo
import json, pprint, requests, argparse, csv, logging, sys, base64



def showLogo():
	print(r"""
	 ___  ________  ________  ________  ________  ___  ___  _________   
	|\  \|\   __  \|\   ____\|\   ____\|\   __  \|\  \|\  \|\___   ___\ 
	\ \  \ \  \|\  \ \  \___|\ \  \___|\ \  \|\  \ \  \\\  \|___ \  \_| 
	 \ \  \ \   ____\ \_____  \ \  \    \ \  \\\  \ \  \\\  \   \ \  \  
	  \ \  \ \  \___|\|____|\  \ \  \____\ \  \\\  \ \  \\\  \   \ \  \ 
	   \ \__\ \__\     ____\_\  \ \_______\ \_______\ \_______\   \ \__\
	    \|__|\|__|    |\_________\|_______|\|_______|\|_______|    \|__|
	                  \|_________|                                      
	                                                                    
	                                                                    """)


def compileCreds():

	def compileXforceCreds(XforceCreds):
		#create global dictionary
		global APIXFORCE
		APIXFORCE = {}

		APIXFORCE['key'] = XforceCreds[1]
		APIXFORCE['password'] = XforceCreds[2]


	#Take creds from csv, populate global variables
	#Xforce creds must be the first row due to the key / password format
	logging.debug('Commence cred compile')
	creds = []

	credsPath = './creds.csv'
	with open(credsPath, 'r') as infile:
		reader = csv.reader(infile)

		for row in reader:
			creds.append(row)

		#create XForce variabe and remove from creds list
		compileXforceCreds(creds[0])
		creds = creds[1:]

	#iterate over list, set index 0 as the variable name, index 1 as the value
	for i in creds:
		globals()[i[0]] = i[1]
        

def getXForceOutput(ip):

	def createB64(api_key, api_password):
		#encode api creds for use with API

		string_format = f'{api_key}:{api_password}'.encode()
		base64_format = f'Basic {base64.b64encode(string_format).decode()}'

		return base64_format


	url = f'https://api.xforce.ibmcloud.com/api/ipr/{ip}'
	headers = {'Authorization': createB64(APIXFORCE['key'], APIXFORCE['password'])}

	response = requests.get(url, headers=headers)

	return json.loads(response.text)


def getShodanOutput(ip):
	client = Shodan(APIshodan)

	try:
		output = client.host(ip)
	except:
		#account for no shadan data available

		details = {}
		details['ports'] = 'No Data Available'

		return details
	
	return output


def getIPInfoOutput(ip):
	#queries ipinfo, view all data with <print(details.all)>

	client = ipinfo.getHandler(APIipinfo)
	details = client.getDetails(ip)

	return details.all


def getVTOutput(ip):

	url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	params = {'apikey':APIvt,'ip': ip}
	response = requests.get(url, params=params)

	#check for empty reponse
	if response.status_code == 204:
		return None

	return json.loads(response.text)


def reverseIPLookup(ip):
	#queries hackertarget for url list, returns list object

	urls = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}').text
	urlList = urls.splitlines()

	return urlList


def getAbuseIPDBOutput(ip):
	# Defining the api-endpoint
	url = 'https://api.abuseipdb.com/api/v2/check'

	querystring = {
	    'ipAddress': ip,
	    'maxAgeInDays': '90'
	}

	headers = {
	    'Accept': 'application/json',
	    'Key': APIabused
	}

	response = requests.request(method='GET', url=url, headers=headers, params=querystring)

	return json.loads(response.text)


def getVpnapiOutput(ip):

	url = f'https://vpnapi.io/api/{ip}?key={APIVPN}'
	response = requests.request(method='GET', url=url)

	return json.loads(response.text)


def dictToJson(dictIn, outfile):
	# Convert dictionary <dictIn> to JSON and write to file <OUTFILE>

	with open(outfile, "w") as outputFile: 
		jsonObject = json.dumps(dictIn, indent = 4)
		outputFile.write(jsonObject)

		#return jsonObject


def getHistoricUrls(vtOutput):
	#compile list of historic Urls as reported by VirusTotal
	#returns dict

	historicUrls = []
	
	if (len(vtOutput['resolutions']) > 0):

		for i in vtOutput['resolutions']:
			historicUrls.append(i)

	#order by date desc
	historicUrls = sorted(historicUrls, key=itemgetter("last_resolved"), reverse=True)

	return historicUrls


def getIPApiOutput(ip):
	url = f'http://api.ipapi.com/api/{ip}?access_key={APIIPAIP}'
	response = requests.request(method='GET', url=url)

	return json.loads(response.text)


def parseToOutput(inputData='Stand Alone'):

	def getXforceHistory(num, externalSource=None):
		#returns dict containing the <NUM> most recent detections

		def get_created_date(entry):
			return datetime.strptime(entry['created'], "%Y-%m-%dT%H:%M:%S.%fZ")


		def get_recent_entries(historicData):

			def sort_by_created(entry):
				return get_created_date(entry)


			# Sort the history_data based on the "created" field in descending order
			sorted_history = sorted(historicData, key=sort_by_created, reverse=True)

			# Return the three most recent entries
			return sorted_history[:num]

		#account for key deviations when run externally
		if externalSource == None:
			return get_recent_entries(xforceOutput['history'])
		else:
			return get_recent_entries(externalSource['xforceOutput']['history'])

	notAvailable = 'Data unavailable'

	#check if being called by external script, if yes, create new object (inputData exists)
	if inputData != 'Stand Alone':
		logging.debug('Called from script')
		output = {}

		#parses multiple sources into a single output object
		output['location'] = inputData['vpnapiOutput'].get('location', notAvailable)
		output['location']['flagURL'] = inputData['ipinfoOutput'].get('country_flag_url', notAvailable)
		output['location']['city'] = inputData['ipinfoOutput'].get('city', notAvailable)
		output['location']['region'] = inputData['ipinfoOutput'].get('region', notAvailable)
		output['network'] = inputData['vpnapiOutput'].get('network', notAvailable)
		output['network']['isp'] = inputData['abuseIPDBOutput']['data']['isp']
		output['network']['usageType'] = inputData['abuseIPDBOutput']['data']['usageType']
		output['network']['domain'] = inputData['abuseIPDBOutput']['data']['domain']
		output['VPNData'] = {}
		output['VPNData']['VPN'] = inputData['vpnapiOutput']['security']['vpn']
		output['VPNData']['TOR'] = inputData['vpnapiOutput']['security']['tor']
		output['VPNData']['Proxy'] = inputData['vpnapiOutput']['security']['proxy']
		output['VPNData']['Relay'] = inputData['vpnapiOutput']['security']['relay']
		output['ports'] = inputData['shodanOutput'].get('ports', notAvailable)
		output['ip'] = inputData['vpnapiOutput'].get('ip', notAvailable)
		output['flag'] = inputData.get('ipapiOutput', {}).get('location', {}).get('country_flag', notAvailable)		
		output['historicURLs'] = inputData.get('historicUrls', notAvailable)
		output['abuseIPDBDetections'] = {}
		output['abuseIPDBDetections']['totalReports'] = inputData['abuseIPDBOutput']['data']['totalReports']
		output['abuseIPDBDetections']['lastReport'] = inputData['abuseIPDBOutput']['data']['lastReportedAt']
		output['abuseIPDBDetections']['score'] = inputData['abuseIPDBOutput']['data']['abuseConfidenceScore']
		output['xforceData'] = {}
		output['xforceData']['score'] = inputData['xforceOutput'].get('score', notAvailable)
		output['xforceData']['categories'] = inputData['xforceOutput'].get('cats', notAvailable)
		output['xforceData']['history'] = getXforceHistory(2, inputData)
		
		if inputData['vtOutput'] is not None:
			output['historicURLs'] = getHistoricUrls(inputData['vtOutput'])
		else:
			output['historicURLs'] = []

		return output

	else:

		#parses multiple sources into a single output object
		logging.debug('Called from main')

		output = {}
		output['location'] = vpnapiOutput.get('location', notAvailable)
		output['location']['flagURL'] = ipinfoOutput.get('country_flag_url', notAvailable)
		output['location']['city'] = ipinfoOutput.get('city', notAvailable)
		output['location']['region'] = ipinfoOutput.get('region', notAvailable)
		output['network'] = vpnapiOutput.get('network', notAvailable)
		output['network']['isp'] = abuseIPDBOutput['data']['isp']
		output['network']['usageType'] = abuseIPDBOutput['data']['usageType']
		output['network']['domain'] = abuseIPDBOutput['data']['domain']
		output['VPNData'] = {}
		output['VPNData']['VPN'] = vpnapiOutput['security']['vpn']
		output['VPNData']['TOR'] = vpnapiOutput['security']['tor']
		output['VPNData']['Proxy'] = vpnapiOutput['security']['proxy']
		output['VPNData']['Relay'] = vpnapiOutput['security']['relay']
		output['ports'] = shodanOutput.get('ports', notAvailable)
		output['ip'] = vpnapiOutput.get('ip', notAvailable)
		output['flag'] = ipapiOutput.get('location', {}).get('country_flag', 'NONE')
		output['historicURLs'] = historicUrls
		output['vtDetections'] = vtOutput.get('detected_urls', notAvailable)
		output['abuseIPDBDetections'] = {}
		output['abuseIPDBDetections']['totalReports'] = abuseIPDBOutput['data']['totalReports']
		output['abuseIPDBDetections']['lastReport'] = abuseIPDBOutput['data']['lastReportedAt']
		output['abuseIPDBDetections']['score'] = abuseIPDBOutput['data']['abuseConfidenceScore']
		output['xforceData'] = {}
		output['xforceData']['score'] = xforceOutput.get('score', notAvailable)
		output['xforceData']['categories'] = xforceOutput.get('cats', notAvailable)
		output['xforceData']['history'] = getXforceHistory(10)

		return output


def compileJSONData():
	allData = {}
	allData['xforceOutput'] = xforceOutput
	allData['vpnapiOutput'] = vpnapiOutput
	allData['abuseIPDBOutput'] = abuseIPDBOutput
	allData['vtOutput'] = vtOutput
	allData['shodanOutput'] = shodanOutput
	allData['ipinfoOutput'] = ipinfoOutput
	allData['ipapiOutput'] = ipapiOutput

	return allData


def buildJSONOnly(ip):
	#for use in external applications, returns enriched object
	logging.info('Building JSON - ipscout')

	compileCreds()

	ipapiOutput = getIPApiOutput(ip)
	xforceOutput = getXForceOutput(ip)
	vpnapiOutput = getVpnapiOutput(ip)
	abuseIPDBOutput = getAbuseIPDBOutput(ip)
	vtOutput = getVTOutput(ip)
	ipinfoOutput = getIPInfoOutput(ip)
	shodanOutput = getShodanOutput(ip)

	#account for bad response from VT
	if not vtOutput == None:
		historicUrls = getHistoricUrls(vtOutput)
	else:
		historicUrls = []

	#compile
	allData = {}
	allData['xforceOutput'] = xforceOutput
	allData['vpnapiOutput'] = vpnapiOutput
	allData['abuseIPDBOutput'] = abuseIPDBOutput
	allData['vtOutput'] = vtOutput
	allData['shodanOutput'] = shodanOutput
	allData['ipinfoOutput'] = ipinfoOutput
	allData['ipapiOutput'] = ipapiOutput

	return allData


def buildHTML(output):

	def writeHTMLToFile(html):

		logging.debug("Write HTML to file")

		text_file = open("index.html", "w")
		text_file.write(html)
		text_file.close()


	def boilerplate():
		logging.debug('Adding Boilerplate')
		html = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport"content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-UA-Compatible"content="ie=edge">\n<title>IP Scout</title>\n<link rel="stylesheet"href="styles.css">\n</head>\n<body>'
		
		return html


	def addLocationDiv(html):

		locationDIV = f'<div><h2>Location</h2><table>\
		<tr><th>Country</th><td>{output["location"]["country"]}</td></tr>\
		<tr><th>Region</th><td>{output["location"]["region"]}</td></tr>\
		<tr><th>City</th><td>{output["location"]["city"]}</td></tr></table>'

		return locationDIV


	def addNetworkDiv(html):
		networkDIV = f'<div><h2>Network</h2>\
		<table><tr><th>CIDR</th>\
		<td>{output["network"]["network"]}</td></tr>\
		<tr><th>ASN</th>\
		<td>{output["network"]["autonomous_system_number"]}</td></tr>\
		<tr><th>ASN Organisation</th>\
		<td>{output["network"]["autonomous_system_organization"]}</td></tr>\
		<tr><th>ISP</th>\
		<td>{output["network"]["isp"]}</td></tr>\
		<tr><th>Usage Type</th>\
		<td>{output["network"]["usageType"]}</td></tr>\
		<tr><th>Domain</th>\
		<td>{output["network"]["domain"]}</td></tr>\
		</table></div>'

		return networkDIV


	def addPortsDiv(html):

		#check that open ports are recorded
		if (output['ports'] == 'No Data Available'):
			return ''

		#compile list of ports
		portsDIV = f'<div><h2>Open Ports</h2>'
		portsDIV += f'<table><tr><td>'

		portList = ''
		
		for port in output['ports']:
			portList += f'{port}, '

		portsDIV += f'{portList[:-2]}<tr></td></table>'

		return portsDIV


	def addHistoricUrls(html):

		#ensure data exists
		if (len(output['historicURLs']) == 0):
			#No history, return nothing
			return ''

		historicUrlsDIV = '<div><h2>Historic URLs</h2>'
		table = '<table><tr><th>URL</th><th>Last Seen</th></tr>'

		for url in output['historicURLs']:
			table += f'<tr><td>{url["hostname"]}</td><td>{url["last_resolved"][:-9]}</td></tr>'

		table += '</table>'

		historicUrlsDIV += (table + '</div>')

		return historicUrlsDIV


	def addXforecHistory(html):
		#check if history exists
		if len(output['xforceData']['history']) == 0:
			return ''

		xforceHistoryDIV = '<div><h2>XForce Detections</h2>'

		#create detections table, set quantity in <parseToOutput()>
		table = '<table><tr><th>Timestamp</th><th>Reporting Country</th><th>Reason</th><th>Confidence</th></tr>'

		for i in output['xforceData']['history']:
			country = i.get('geo', {}).get('country', 'notAvailable')

			table += f'<tr><td>{i["created"][:10]}</td><td>{country}</td><td>{i["reason"]}</td><td>{i["score"] * 10}%</td></tr>'

		table += '</table>'

		xforceHistoryDIV += table + '</div>'

		return xforceHistoryDIV


	def addHeaderDiv(html):

		logging.debug('Adding header div')



		headerDIV = f'<div class="header">'
		headerDIV += f'<h1>{output["ip"]}</h1>'
		headerDIV += f'<img src="{output["flag"]}" alt="{output["location"]["country_code"]}_flag" style="width: 5vw; height: auto;"/>'
		headerDIV += '</div>'
		
		return headerDIV 
		

	def addDetectionsDiv():
		#build table div from detection engines

		detectionsDIV = '<div><h2>Detections</h2>'
		abuseIPDBDIV = '<div><table><tr><th colspan="2"><h3>AbuseIPDB</h3></th></tr>'
		
		#add AbuseIPDB data
		if output['abuseIPDBDetections']['totalReports'] > 0:
			abuseIPDBDIV += f'<tr><th>Hostile</th><td>{output["abuseIPDBDetections"]["score"]}%</td></tr>\
			<tr><th>Reports</th><td>{output["abuseIPDBDetections"]["totalReports"]}</td></tr>\
			<tr><th>Last Report</th><td>{output["abuseIPDBDetections"]["lastReport"][:-9]}</td></tr>'
		else:
			abuseIPDBDIV += f'<tr><td colspan="2">No Reports</td></tr>'

		abuseIPDBDIV += "</table></div>"

		#add Xforce data
		xforceDIV = '<div><table><tr><th colspan="2"><h3>IBM XForce</h3></td></tr>'
		xforceDIV += f'<tr><th>Hostile</th><td>{int(output["xforceData"]["score"] * 10)}%</td></tr>'

		#add XForce categories
		for key, value in output['xforceData']['categories'].items():
			xforceDIV += f'<tr><th>{key}</th><td>{value}%</td></tr>'

		xforceDIV += "</table></div>"

		#add VT detections
		vtDIV = '<div><table><tr><th colspan="3"><h3>VirusTotal</h3></td></tr>'

		if len(output['vtDetections']) == 0:
			return vtDIV + '<tr><td colspan="3">No Reports</td></tr></table></div>'

		vtDIV += '<tr><td>URL</td><td>Scan Date</td><td>% Hostile</td></tr>'

		for i in output['vtDetections']:
			percent = int(int(i["total"]) / int(i["positives"]))
			vtDIV += f'<tr><th>{i["url"]}</th><td>{i["scan_date"][:-9]}</td><td>{percent}%</td></tr>'

		vtDIV += '</table></div>'

		detectionsDIV += abuseIPDBDIV + xforceDIV + vtDIV + '</div>'

		return detectionsDIV


		def vpnDIV():
			#build table div from vpnapi data

			vpnDIV = f'<div><table>'

			for key, value in output["VPNData"].items():

				if value:
					vpnDIV += f'<tr class="highlight"><td>{key}</td><td>{value}</td></tr>'
				else:
					vpnDIV += f'<tr class="dull"><td>{key}</td><td>{value}</td></tr>'

			return vpnDIV + '</table></div>'


	def addVpnDiv():
		#build table div from vpnapi data

		vpnDIV = f'<div><table>'

		for key, value in output["VPNData"].items():

			if value:
				vpnDIV += f'<tr class="highlight"><td>{key}</td><td>{value}</td></tr>'
			else:
				vpnDIV += f'<tr class="dull"><td>{key}</td><td>{value}</td></tr>'

		return vpnDIV + '</table></div>'


	html = boilerplate()
	html += addHeaderDiv(html)
	html += addLocationDiv(html)
	html += addNetworkDiv(html)
	html += addVpnDiv()
	html += addDetectionsDiv()

	html += addPortsDiv(html)
	html += addHistoricUrls(html)
	html += addXforecHistory(html)
	html += '</body>\n</html>'

	writeHTMLToFile(html)

#prevent entire script from running when using as an import source
if __name__ == "__main__":

	#parse arguments
	parser = argparse.ArgumentParser(description='A commandline tool to retrieve metadata about an IP from multiple sources.')
	parser.add_argument('-i', type=str, default='8.8.8.8', help='The IP address to scout')
	parser.add_argument('-o', type=str, default='ipscout.json', help='JSON output file name')
	args=parser.parse_args()

	#set variables
	ip = args.i
	outfile = args.o
	output = {}
	logfile = 'ipScout.log'
	noRender = False

	#configure logger
	logging.basicConfig(handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(logfile, mode="a"),],level=logging.DEBUG,format='%(asctime)s[%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S',)

	showLogo()

	compileCreds()
	ipapiOutput = getIPApiOutput(ip)
	xforceOutput = getXForceOutput(ip)
	vpnapiOutput = getVpnapiOutput(ip)
	abuseIPDBOutput = getAbuseIPDBOutput(ip)
	vtOutput = getVTOutput(ip)
	ipinfoOutput = getIPInfoOutput(ip)
	shodanOutput = getShodanOutput(ip)
	historicUrls = getHistoricUrls(vtOutput)

	allData = compileJSONData()

	output = parseToOutput()
	dictToJson(output, outfile)
	dictToJson(allData, 'allData.json')

	if not noRender:
		buildHTML(output)
