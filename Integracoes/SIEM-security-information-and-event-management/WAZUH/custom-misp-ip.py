#!/var/ossec/framework/python/bin/python3
## MISP API Integration
#
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re
import logging

logging.basicConfig(filename='/var/ossec/integrations/misp.log',  format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = "{0}/queue/sockets/queue".format(pwd)


def adicionar_ip_na_blocklist(ip, caminho='/var/ossec/integrations/blocklist/blocklist.txt'):
    # Garante que o diretório exista
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    # Se o arquivo não existir, cria
    if not os.path.isfile(caminho):
        with open(caminho, 'w') as f:
            pass
    # Lê os IPs existentes
    with open(caminho, 'r') as f:
        ips_existentes = {linha.strip() for linha in f if linha.strip()}
    # Verifica se o IP já está na lista
    if ip in ips_existentes:
        #print(f"O IP {ip} já está na blocklist.")
        return False
    # Adiciona o IP ao arquivo
    with open(caminho, 'a') as f:
        f.write(ip + '\n')
    #print(f"O IP {ip} foi adicionado à blocklist.")
    return True




def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:misp:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


false = False
# Read configuration parameters
alert_file = open(sys.argv[1])

# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()


# New Alert Output if MISP Alert or Error calling the API
alert_output = {}
# MISP Server Base URL
misp_base_url = "https://SEUENDERECOMISP/attributes/restSearch/"
# MISP Server API AUTH KEY
misp_api_auth_key = "Insira sua Auth Key do MISP aqui"
# API - HTTP Headers
misp_apicall_headers = {
    "Content-Type": "application/json",
    "Authorization": f"{misp_api_auth_key}",
    "Accept": "application/json",
}


ip_consulta=""
import ipaddress

def allowlist(ip):
    ranges = [
        ipaddress.IPv4Network("Insira o range de IP aqui"),
        ipaddress.IPv4Network("Insira o range de IP aqui")
    ]

    # Converte o IP informado para o formato IPv4Address
    ip = ipaddress.IPv4Address(ip)

    # Verifica se o IP está em alguma das faixas
    for network in ranges:
        if ip in network:
            return True

    return False


try:
    srcip = alert['data'].get('srcip')
    if not srcip:
        exit()
    id = alert['rule'].get('id')
    if id in ['651','100622'] :
        logging.warning("ID nao permitido: " + str(id))
        exit()
    #import json
    #arq = open('/var/ossec/integrations/arq.json','w')
    #arq.write(json.dumps(alert))
    #arq.close()

except:
    exit()


def process_alert(alert):
    try:
        srcip = alert['data'].get('srcip')
        # Verifica se o IP de origem é privado
        if ipaddress.ip_address(srcip).is_private:
            dstip = alert['data'].get('dstip')
            logging.warning("DstIP também é privado. Encerrando.")

            # Verifica se o IP de destino também é privado
            if ipaddress.ip_address(dstip).is_private:
                logging.warning("DstIP também é privado. Encerrando.")
                return False
            else:
                if not allowlist(dstip):
                    return dstip
        if not allowlist(srcip):
            return srcip
        else:
            return False
    except Exception as e:
        return False
        logging.warning(f"Erro inesperado: {e}")



if alert['data']['srcip']:
    wazuh_event_param = process_alert(alert)
    logging.warning(wazuh_event_param)

    if not wazuh_event_param:
        exit()

    misp_search_value = "value:" f"{wazuh_event_param}"
    misp_search_url = "".join([misp_base_url, misp_search_value])


    try:

        misp_api_response = requests.get(
            misp_search_url, headers=misp_apicall_headers, verify=False
        )

        logging.warning(misp_api_response.json())

    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = "Connection Error to MISP API"
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        #logging.warning(misp_api_response.json())
        #print(misp_api_response)

        # Check if response includes Attributes (IoCs)
        if misp_api_response["response"]["Attribute"]:
            # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["integration"] = "misp"
            alert_output["misp"]["source"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            if alert_output["misp"]["type"] not in ["ip-src"]:
                 exit()
            alert_output["misp"]["source"]["description"] = alert["rule"]["description"]
            alert_output["misp"]["event_info"] = misp_api_response["response"]["Attribute"][0]["Event"]["info"]

            ip = srcip = alert['data'].get('srcip')

            adicionar_ip_na_blocklist(ip)
            logging.warning("Adicionando a blocklist: " + ip )

            send_event(alert_output, alert["agent"])
else:
    sys.exit()