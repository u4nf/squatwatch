#ipscout modules
from shodan import Shodan
from datetime import datetime
from operator import itemgetter
from PIL import Image
import ipinfo
import json, pprint, requests, argparse, csv, logging, sys, base64, os, re, base64
import subprocess
import ipscout as IPS


#parse arguments
parser = argparse.ArgumentParser(description='A commandline tool to retrieve metadata about an IP from multiple sources.')
parser.add_argument('-d', type=str, default='google.com', help='The Domain to check')
parser.add_argument('-o', type=str, default='squatwatch.json', help='Curated JSON output file name')
parser.add_argument('-t', type=str, default='twist.json', help='Squat data output file name')
args=parser.parse_args()

#set variables
domain = args.d
outfile = args.o
twistOut = args.t

output = {}
basePath = './'
logfile = 'squatwatch.log'

noRender = False

#configure logger
logging.basicConfig(
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(basePath + logfile, mode="a"),
    ],
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s]: %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',)


def showLogo():
	print(r"""
	 _______  _______           _______ _________          _______ _________ _______          
	(  ____ \(  ___  )|\     /|(  ___  )\__   __/|\     /|(  ___  )\__   __/(  ____ \|\     /|
	| (    \/| (   ) || )   ( || (   ) |   ) (   | )   ( || (   ) |   ) (   | (    \/| )   ( |
	| (_____ | |   | || |   | || (___) |   | |   | | _ | || (___) |   | |   | |      | (___) |
	(_____  )| |   | || |   | ||  ___  |   | |   | |( )| ||  ___  |   | |   | |      |  ___  |
	      ) || | /\| || |   | || (   ) |   | |   | || || || (   ) |   | |   | |      | (   ) |
	/\____) || (_\ \ || (___) || )   ( |   | |   | () () || )   ( |   | |   | (____/\| )   ( |
	\_______)(____\/_)(_______)|/     \|   )_(   (_______)|/     \|   )_(   (_______/|/     \|
                                                                                          
                                                                          """)


def runTwist(domain):
	#Runs the external dnstwist script saves as JSON and screens.

	logging.debug(f'Commencing twist - {domain}')
	print('This may take a while, expect results within 5 min if the domain is approx 15 chars')
	subprocess.run(["python3", "dnstwist.py", "-wrgp", "--screenshots", "screens", "--format", "json", "-o", f"{twistOut}", f"{domain}"])


def enrich(data):

	def runIPScout(ip):

		#run ipscout and return ip intel object
		return IPS.buildJSONOnly(ip)


	ipPattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

	for index, squat in enumerate(data):

		print(squat)
		#check if valid ip is returned, if yes, enrich
		ip = squat.get("dns_a", [None])[0]
		logging.debug(f'Verifying {ip} is a valid IPV4')


		if re.match(ipPattern, ip) is not None:

			logging.debug(f'Enriching {ip} via ipscout')
			ipscout = runIPScout(ip)
		else:
			ipscout = None


		data[index]['ipscout'] = ipscout

	return data


def importJSON():

	logging.debug('Commence JSON import')
	
	with open(f'{twistOut}') as json_file:
		return json.load(json_file)


def buildHTML(data):

	#parses data and builds HTML page
	logging.debug('Commence HTML build')

	def writeHTMLToFile(html):

		text_file = open("index.html", "w")
		text_file.write(html)
		text_file.close()


	def boilerplate():
		html = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport"content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-UA-Compatible"content="ie=edge">\n<title>Squatwatch</title>\n<link rel="stylesheet"href="styles.css">\n</head>\n<body>'

		html += f'<section class="mainTitle"><h1>Potential squatting domains for <span class="titleDomain">{domain}</span><h1></section>'
		
		return html


	def getScreenshot(domName):
		#Check if screenshot exists, shrink and return as b64 for embedding

		screensDir = 'screens'
		screenshotName = None

		#find screenshot
		files = os.listdir(screensDir)
		
		for filename in files:
		    if filename.endswith('_' + domName + '.png'):
		        screenshotName = filename
		        break

		if screenshotName == None:
			screenshotName = 'noScreen.png'

		#resize
		image = Image.open(screensDir + '/' + screenshotName)
		image.thumbnail((150,150))
		image.save(screensDir + '/thumb_' + screenshotName)

		#get b64 as string
		with open(screensDir + "/thumb_" + screenshotName, 'rb') as image_file:
			b64out = base64.b64encode(image_file.read())
			b64out = b64out.decode('utf-8')

		return b64out


	def domainsSection(domain):
		html = '<section>'
		noDataMsg = 'NULL'
		
		domName = domain.get("domain", noDataMsg)
		ip = domain.get("dns_a", [noDataMsg])[0]
		country = domain.get("geoip", noDataMsg)
		created = domain.get("whois_created", noDataMsg)
		registrar = domain.get("whois_registrar", noDataMsg)
		flag = domain["enrich"]["location"]["flagURL"]
		screenshot = getScreenshot(domName)

		numCols = str(4)

		ipElement = f'<td style="width: 50px; height: calc(100px * (3 / 2)); background-image: url({flag}); background-size: 100% 100%; background-repeat: no-repeat;"><h3 class="ip">{ip}<h3></td>'

		screenElement = f'<td style="background-image: url(\'data:image/png;base64,{screenshot}\'); background-size: contain; background-position: center; background-repeat: no-repeat;"></td>'

		html += f'<div class="domname"><h2><a href="http://{domName}" target="_blank">{domName}</a></h2></div><details><summary><div>\
		    <table class="summarised" style="--num-cols: {numCols};"><tr><th>IP Address</th><th>Country</th><th>Registered</th><th>ScreenShot</th></tr>\
		    <tr>{ipElement}<td>{country}</td><td><h4>{created}<br><br>{registrar}</h4></td>{screenElement}</tr></table></div></summary>'

		return html


	def ipScoutSection(enrich):

		noDataMsg = 'NULL'

		#network
		asn = enrich["network"]["autonomous_system_number"]
		asnOrg = enrich["network"]["autonomous_system_organization"]
		network = enrich["network"]["network"]
		isp = enrich["network"]["isp"]
		usageType = enrich["network"]["usageType"]

		#location
		city = enrich["location"]["city"]
		region = enrich["location"]["region"]
		country = enrich["location"]["country"]

		#VPN
		VPN = enrich["VPNData"]["VPN"]
		TOR = enrich["VPNData"]["TOR"]
		proxy = enrich["VPNData"]["Proxy"]
		relay = enrich["VPNData"]["Relay"]

		ports = enrich["ports"]
		xforceScore = enrich['xforceData']['score']
		xforceCat = enrich['xforceData']['categories']

		vtDetections = enrich['vtDetections']
		historicURLs = enrich['historicURLs']


		html = '<div class="intel"><table>'

		html += f'<tr><th>Country</th><td>{country}</td></tr>'
		html += f'<tr><th>Region</th><td>{region}</td></tr>'
		html += f'<tr><th>City</th><td>{city}</td></tr>'
		html += f'<tr><th>ASN</th><td>{asn}</td></tr>'
		html += f'<tr><th>Organisation</th><td>{asnOrg}</td></tr>'
		html += f'<tr><th>Network</th><td>{network}</td></tr>'
		html += f'<tr><th>ISP</th><td>{isp}</td></tr>'
		html += f'<tr><th>Type</th><td>{usageType}</td></tr>'
		html += f'<tr><td colspan="2"></td></tr>'
		html += f'<tr><th>XForce Score</th><td>{int(xforceScore * 10)}% Hostile</td></tr>'

		#iterate over categories
		for i in xforceCat.keys():
			html += f'<tr class="xforce"><th>{i}</th><td>{enrich["xforceData"]["categories"][i]}% confidence</td></tr>'


		html += '</table></div></details></section><hr>'

		return html


	html = boilerplate()

	for i, j in enumerate(data):
		html += domainsSection(data[i])
		html += ipScoutSection(data[i]['enrich'])

	writeHTMLToFile(html)

"""
#delete old data
if os.path.exists(twistOut):
	logging.debug(f'Deleting old file - {twistOut}')
	os.remove(twistOut)
"""
showLogo()

#runTwist(domain)
data = importJSON()
#enrich with ipscout data
data = enrich(data)

#curate API data one IP at a time
for i in data:
	
	enriched = IPS.parseToOutput(i['ipscout'])
	i['enrich'] = enriched

	#delete the superfluous data
	del i['ipscout']


IPS.dictToJson(data, 'test.json')
"""

with open(f'test.json') as json_file:
	data = json.load(json_file)
"""
buildHTML(data)
