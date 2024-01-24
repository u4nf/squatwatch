import subprocess, json, logging, sys

domain = 'secure-iss.com'
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
	subprocess.run(["python3", "dnstwist.py", "-wrgp", "--screenshots", "screens", "--format", "json", "-o", f"{twistOut}", f"{domain}"])


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
		html = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport"content="width=device-width, initial-scale=1.0">\n<meta http-equiv="X-UA-Compatible"content="ie=edge">\n<title>IP Scout</title>\n<link rel="stylesheet"href="styles.css">\n</head>\n<body>'
		
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

			html += f'<div><h2>{domName}</h2><h3>{ip}<h3><h4>{country}<h4><h4>{created}</h4><h4>{registrar}</h4></div>'

		html += '</section>'

		return html


	html = boilerplate()
	html += domainsSection()

	writeHTMLToFile(html)


showLogo()
#runTwist(domain)
data = importJSON()

buildHTML(data)
