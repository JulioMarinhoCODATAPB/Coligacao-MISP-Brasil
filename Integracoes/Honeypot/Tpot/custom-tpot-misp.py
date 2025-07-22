import datetime
import logging
import ipaddress
import urllib3
from pymisp import MISPEvent, PyMISP
from elasticsearch import Elasticsearch

# Suprime o aviso de HTTPS não verificado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configurações
MISP_URL = "<URL_MISP_SERVER>"
MISP_KEY = "<API_KEY_MISP>"
MISP_VERIFYCERT = True   # Coloque False se a url nao for certificada
HONEYPOT_IP = "<IP_HONEYPOT_SERVER>"
ES_HOST = "<IP_E_PORTA_ELASTICSEARCH>"
ES_INDEX = "logstash-*"

# Logger
logging.basicConfig(
    filename='/var/log/tpot-misp_errors.log',   # Log de erros
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()

# Inicializa MISP e Elasticsearch
misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
es = Elasticsearch(ES_HOST)

# Função allowlist

def allowlist(ip):
    ranges = [
        ipaddress.IPv4Network("<IP_RANGE>"),
        ipaddress.IPv4Network("<IP_RANGE>")
    ]
    ip_obj = ipaddress.IPv4Address(ip)
    if ip == HONEYPOT_IP:
        return False  # exceção para o IP do honeypot
    for network in ranges:
        if ip_obj in network:
            return True
    return False

# Controle de eventos e IPs
evento_atual = None
evento_criado_em = None
ip_cache = set()

# Loop principal
while True:
    agora = datetime.datetime.now()

    # Verifica se é necessário criar novo evento
    if evento_atual is None or (agora - evento_criado_em).total_seconds() >= 86400:  # Cria um novo evento a cada 24 horas
        if evento_atual is not None:
            try:
                misp.publish(evento_atual)
                logger.info(f"[INFO] Evento {evento_atual['Event']['id']} publicado com sucesso.")
            except Exception as e:
                logger.error(f"[ERRO] Falha ao publicar evento {evento_atual['Event']['id']}: {e}")

        novo_evento = MISPEvent()
        novo_evento.info = f"Ataques no Honeypot - {agora.strftime('%d-%m-%Y')}"
        novo_evento.analysis = 2
        novo_evento.published = False
        novo_evento.distribution = 4      # 4 = Sharing Group; 0= Your Organization Only
        novo_evento.sharing_group_id = 5  # id da Sharing Group selecionada
        novo_evento.threat_level_id = 3   # 1= High; 2=Medium; 3=Low
        novo_evento.add_tag("tlp:green")    #Tag TLP
        novo_evento.add_tag("Honeypot")     #Tag Honeypot
        novo_evento.add_tag('enisa:nefarious-activity-abuse="distributed-denial-of-network-service-amplification-reflection-attack"')   #Tag ENISA

        evento_atual = misp.add_event(novo_evento)
        evento_criado_em = agora
        ip_cache.clear()
        logger.info(f"[INFO] Novo evento criado com ID {evento_atual['Event']['id']}")

    # Busca novos IPs no Elasticsearch
    try:
        r = es.search(index=ES_INDEX, query={"query_string": {"query": f"timestamp:[now-2m TO now] AND NOT geoip.ip: {HONEYPOT_IP}"}}, size=10)   # Se aumentar o numero de requests, aumenta a carga de rede e hardware
    except Exception as e:
        logger.error(f"[ERRO] Falha na busca do Elasticsearch: {e}")
        continue

    for hit in r['hits']['hits']:
        try:
            src_ip = hit['_source']['geoip']['ip']
            if src_ip in ip_cache:
                continue
            if allowlist(src_ip):
                continue
            ip_cache.add(src_ip)

            # Tenta extrair a porta de diferentes possíveis localizações
            port = None
            if 'destination' in hit['_source'] and isinstance(hit['_source']['destination'], dict):
                port = hit['_source']['destination'].get('port')
            elif 'dest_port' in hit['_source']:
                port = hit['_source']['dest_port']
            elif 'destination_port' in hit['_source']:
                port = hit['_source']['destination_port']

            # Ignora conexões HTTP
            if str(port) == "80":
               continue


            # Cria o atributo IP
            attribute = {
                "type": "ip-src",
                "value": src_ip
            }
            attribute_response = misp.add_attribute(evento_atual['Event']['id'], attribute)

            # Aplica tags ao atributo se possível
            if 'Attribute' in attribute_response and 'uuid' in attribute_response['Attribute']:
                uuid = attribute_response['Attribute']['uuid']

                # Adiciona tag da porta
                if port:
                    try:
                        misp.tag(uuid, f"dst-port:{port}")
                    except Exception as tag_error:
                        logger.warning(f"[AVISO] Não foi possível adicionar tag de porta {port} ao IP {src_ip}: {tag_error}")

                # Adiciona tag de país se disponível
                country = hit['_source'].get('geoip', {}).get('country_name')
                if country:
                    try:
                        misp.tag(uuid, f"country:{country}")
                    except Exception as tag_error:
                        logger.warning(f"[AVISO] Não foi possível adicionar tag de país '{country}' ao IP {src_ip}: {tag_error}")

        except Exception as e:
            logger.error(f"[ERRO] Falha ao adicionar IP {src_ip}: {e}")
root@<yourserverhostname>:/opt/integrations#
