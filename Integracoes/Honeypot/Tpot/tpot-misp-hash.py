#!/usr/bin/env python3

import datetime
import logging
import urllib3
import ipaddress
from pymisp import PyMISP, MISPEvent, MISPAttribute
from elasticsearch import Elasticsearch
from collections import defaultdict
import os


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Desabilita alertas de url nao certificada

# --- CONFIGURACAO INICIAL ---
MISP_URL = "<URL_MISP_SERVER>"
MISP_KEY = "<API_KEY_MISP>"
MISP_VERIFYCERT = True # Coloque False se a url nao for certificada
ES_HOST = "<IP_E_PORTA_ELASTICSEARCH>"
ES_INDEX = "logstash-*"
# --- FIM DA CONFIGURACAO ---


# --- LISTA DE IPs LIBERADOS ---
ALLOWLISTED_RANGES = [
    "<IP_RANGE>",
    "<IP_RANGE>"
]


# --- Logger Setup ---
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(script_dir, 'daily_misp_import.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()


def allowlist(ip_string: str) -> bool:
    """
    Checa se um endereco IP esta no range de rede permitido (ALLOWLISTED_RANGES).

    :param ip_string: O endereco IP a ser checado.
    :return: True se o IP esta na allowlist, se nao, False.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        for network_str in ALLOWLISTED_RANGES:
            if ip_obj in ipaddress.ip_network(network_str): return True # IP esta no range permitido
        return False # IP nao esta no range permitido
    except ValueError:
        logger.warning(f"'{ip_string}' nao e um endereco IP valido.") # A string nao e um endereco IP valido
        return False

def _tag_attribute(misp: PyMISP, uuid: str, source: dict, connection_info: dict):
    """Funcao que adiciona tags de geolocalizacao e porta de destino para o atributo IP."""
    ip_addr = source.get('src_ip')
    
    if source.get('geoip', {}).get('country_name'):
        try:
            misp.tag(uuid, f"country:{source['geoip']['country_name']}")
            logger.info(f"  -> Tagged IP {ip_addr} with country: {source['geoip']['country_name']}")
        except Exception as e: logger.warning(f"  -> Failed to tag country for IP {ip_addr}: {e}")
    
    if connection_info.get('dst_port'):
        try:
            misp.tag(uuid, f"dst-port:{connection_info['dst_port']}")
            logger.info(f"  -> Tagged IP {ip_addr} with dst-port: {connection_info['dst_port']}")
        except Exception as e: logger.warning(f"  -> Failed to tag dst-port for IP {ip_addr}: {e}")


def run_daily_import():
    """
    Se conecta ao servicos, cria um evento MISP e o popula com atributos
    Hashes capturados do Cowrie e os IPs source diretamente associados nas ultimas 24 horas.
    """
    # --- 1. INICIAR CONEXOES ---
    logger.info("Conectando ao MISP e Elasticsearch...")
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        es = Elasticsearch(hosts=[ES_HOST])
        logger.info("Conetado com sucesso com os servicos.")
    except Exception as e: logger.critical(f"[FATAL] Nao conseguiu iniciar os servicos. Erro: {e}"); return

    # --- 2. CRIA UM EVENTO NO MISP ---
    try:
        date_str = datetime.datetime.now().strftime('%d-%m-%y')
        event = MISPEvent(); event.info = f"Hashes de Payload Malware no Honeypot - {date_str}"
        event.distribution = 0; event.threat_level_id = 2; event.analysis = 2
        event.add_tag("tlp:amber+strict"); event.add_tag("Honeypot"); event.add_tag('enisa:nefarious-activity-abuse="worms-trojans"') # Tags do evento
        response_dict = misp.add_event(event)
        event_id = response_dict['Event']['id']
        logger.info(f"Evento MISP criado, ID: {event_id}")
    except Exception as e: logger.error(f"Falha ao criar evento MISP. Erro: {e}"); return

    # --- 3. PROCURA NO ELASTICSEARCH E AGREGA OS DADOS ---
    logger.info("Buscando no Elasticsearch por eventos no Cowrie nas ultimas 24 horas...")
    session_data = defaultdict(lambda: {'ip': None, 'hashes': set(), 'source': {}})
    hash_to_ips_map = defaultdict(set) 
    try:
        query_files = { "bool": { "must": [ { "range": { "@timestamp": { "gte": "now-24h/h" } } }, { "match": { "type": "Cowrie" } }, { "exists": { "field": "shasum" } } ], "filter": [ { "terms": { "eventid": ["cowrie.session.file_download", "cowrie.session.file_upload"] } } ] } } # Mude o valor se quiser colocar outro intervalo de tempo (12h ou 48h por exemplo)
        response_files = es.search(index=ES_INDEX, query=query_files, size=500)
        
        for hit in response_files['hits']['hits']:
            source = hit['_source']
            attacker_ip = source.get('src_ip'); session_id = source.get('session'); sha_hash = source.get('shasum')
            if not attacker_ip or not session_id or not sha_hash or allowlist(attacker_ip): continue
            
            session_data[session_id]['ip'] = attacker_ip
            session_data[session_id]['hashes'].add(sha_hash)
            session_data[session_id]['source'] = source
            hash_to_ips_map[sha_hash].add(attacker_ip) # Populate the new map

        logger.info(f"Encontradas {len(session_data)} sessoes com transferencia de arquivo com {len(hash_to_ips_map)} hashes unicos.")
    except Exception as e: logger.error(f"Falha ao buscar no Elasticsearch. Erro: {e}"); return

    if not session_data:
        logger.info("Sem novos indicadores encontrados nas ultimas 24 horas. Encerrando."); return

    # --- 4. ACHA A PORTA DE CONEXAO ---
    logger.info("Buscando os detalhes da conexao")
    session_connection_info = {}
    session_ids = list(session_data.keys())
    try:
        query_connect = { "bool": { "filter": [ { "match": { "eventid": "cowrie.session.connect" } }, { "terms": { "session.keyword": session_ids } } ] } }
        response_connect = es.search(index=ES_INDEX, query=query_connect, size=len(session_ids))
        
        for hit in response_connect['hits']['hits']:
            source = hit['_source']
            session_id = source.get('session'); dst_port = source.get('dest_port')
            if session_id:
                session_connection_info[session_id] = {'dst_port': dst_port}
        logger.info(f"Achadas informacaoes de {len(session_connection_info)} sessoes.")
    except Exception as e:
        logger.error(f"Falha. Continuando sem a informacao da porta. Erro: {e}")

    # --- 5. PROCESSA OS DADOS AGREGADOS E OS ADICIONA NO MISP ---
    logger.info("Processando dados agregados e adicionando no MISP...")
    processed_ips = set(); processed_hashes = set()  # Cache para evitar adicionar o mesmo IP varias vezes
    for session_id, data in session_data.items():
        ip = data['ip']; connection_info = session_connection_info.get(session_id, {})
        
        if ip and ip not in processed_ips:
            processed_ips.add(ip)
            attr_ip = MISPAttribute(); attr_ip.type = 'ip-src'; attr_ip.value = ip; attr_ip.to_ids = True
            if data['hashes']:
                first_hash = list(data['hashes'])[0]
                attr_ip.comment = f"Utilizou malware com a hash SHA256: {first_hash[:20]}..." # Comentario mostrando o hash que o IP entregou
            response_attr = misp.add_attribute(event_id, attr_ip)
            logger.info(f"Adicionado IP:   {ip}")
            if 'Attribute' in response_attr and 'uuid' in response_attr['Attribute']:
                _tag_attribute(misp, response_attr['Attribute']['uuid'], data['source'], connection_info)
        
        for sha_hash in data['hashes']:
            if sha_hash and sha_hash not in processed_hashes:
                processed_hashes.add(sha_hash)
                attr_hash = MISPAttribute(); attr_hash.type = 'sha256'; attr_hash.value = sha_hash; attr_hash.to_ids = True
                all_ips_for_hash = sorted(list(hash_to_ips_map.get(sha_hash, {ip})))
                attr_hash.comment = f"Utilizada por {len(all_ips_for_hash)} IPs unicos: {', '.join(all_ips_for_hash)}"   # Adicionando um comentario listando todos os IPs que fizeram a entrega do hash  
                misp.add_attribute(event_id, attr_hash)
                logger.info(f"Adicionado HASH: {sha_hash}")
    
    logger.info(f"\n--- SUCCESSO ---")
    logger.info(f"Um total de {len(processed_hashes)} hashes unicas e {len(processed_ips)} IPs unicos associados foram adicionados ao evento {event_id}.")

if __name__ == "__main__":
    run_daily_import()
