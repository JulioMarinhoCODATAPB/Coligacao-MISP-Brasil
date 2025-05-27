from pymisp import (MISPEvent, MISPSighting, MISPTag, MISPOrganisation, MISPObject)
from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup
import argparse
import csv
import requests
import io
import os
import time
import datetime
import json
import sys
import docker
import subprocess
inspect = subprocess.run(['docker', 'inspect', 'elasticsearch'], capture_output=True, text=True)
inspect_data = json.loads(inspect.stdout)
ip_address = inspect_data[0]['NetworkSettings']['Networks']['tpotce_nginx_local']['IPAddress']
honey = "<ip_do_honeypot>"
tpot_url=f"http://{ip_address}:9200"
today=str(datetime.date.today())
from elasticsearch import Elasticsearch
es = Elasticsearch(f"{tpot_url}")
r = es.search(index="logstash-*", query={"query_string": {"query": f"timestamp:[now-30m TO now] AND NOT geoip.ip: {honey}"}}, size=1000)
#r = es.search(index="logstash-*", query={"match_all": {}}, size=5000)
misp_url = "https://misp.brunoodon.com.br"
key = '<api_key>'
misp_verifycert = False
#definindo as características do evento do MISP, que será criado no final
misp = ExpandedPyMISP(misp_url, key, misp_verifycert)
abuse_url = "https://api.abuseipdb.com/api/v2/report"
abuse_key = "<api_key>"
event = MISPEvent()
event.info = "T-Pot Report - "+today+""
event.analysis = "2"
event.published = True
event.distribution = "3" 
event.threat_level_id = "1" #level HIGH
event.add_tag('tlp:green')
event.add_tag('Honeypot')#tag que identifica o tipo de ameaça compartilhada
ioc=[]
for i in r['hits']['hits']:
    try:
        src_ip = i['_source']['geoip']['ip']
        country = i['_source']['geoip']['country_name']
        dst_port = i['_source']['dest_port']
#        print(ioc)
        if not src_ip in '0.0.0.0':
#            print('Attacker:', src_ip, '| Country:', country, '| Targeted port:', dst_port)
            event.add_attribute('ip-src', str(src_ip), disable_correlation=False, to_ids=True)
            event.add_attribute_tag(f"Country:{country}", str(src_ip))
            event.add_attribute_tag(f"Targeted_port:{dst_port}", str(src_ip))
            params = {
    			'ip':''+src_ip+'',
   			'categories': '14,18',
    			'comment':'Honeytrapped'
		     }
            headers = {
    			'Accept': 'application/json',
    			'Key': ''+abuse_key+''
		     }
            response = requests.request(method='POST', url=abuse_url, headers=headers, params=params)
    except:
        print('Not found!')

event = misp.add_event(event)
