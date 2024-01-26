#ipscout modules
from shodan import Shodan
from datetime import datetime
from operator import itemgetter
import ipinfo
import json, pprint, requests, argparse, csv, logging, sys, base64, os, re

import subprocess
import ipscout as IPS

domain = 'illustrious.com'
basePath = './'
logfile = 'dns.log'
twistOut = 'output.json'

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

		#check if valid ip is returned, if yes, enrich
		logging.debug(f'Verifying {squat["dns_a"][0]} is a valid IPV4')
		ip = squat.get("dns_a", [None])[0]


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

		html += f'<section class="mainTitle"><h1>Squatwatch results for <span class="titleDomain">{domain}</span><h1></section>'
		
		return html


	def domainsSection():
		html = '<section>'
		noDataMsg = 'NULL'

		for domain in data:
			domName = domain.get("domain", noDataMsg)
			ip = domain.get("dns_a", [noDataMsg])[0]
			country = domain.get("geoip", noDataMsg)
			created = domain.get("whois_created", noDataMsg)
			registrar = domain.get("whois_registrar", noDataMsg)
			numCols = str(4)

			html += f'<div>\
				<h2>{domName}</h2>\
				<table style="--num-cols: {numCols};"><tr><th>IP Address</th><th>Country</th><th>Registered</th><th>Registrar</th></tr>\
				<tr><td><h3>{ip}<h3></td><td><h4>{country}</h4></td><td><h4>{created}</h4></td><td><h4>{registrar}</h4></td></tr></table></div>'

		html += '</section>'

		return html


	def ipScoutSection():
		#add ip intel
		pass


	html = boilerplate()
	html += domainsSection()

	writeHTMLToFile(html)


#delete old data
if os.path.exists(twistOut):
	logging.debug(f'Deleting old file - {twistOut}')
	os.remove(twistOut)

showLogo()
runTwist(domain)
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

buildHTML(data)
