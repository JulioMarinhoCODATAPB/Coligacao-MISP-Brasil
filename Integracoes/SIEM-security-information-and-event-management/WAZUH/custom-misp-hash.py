#!/var/ossec/framework/python/bin/python3
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import datetime
import time
import requests
import json
import logging
import concurrent.futures
import ipaddress

# --- Início da Configuração Centralizada ---
MISP_VERIFY_SSL = True
MISP_URL = "https://SEUENDERECOMISP/"
MISP_API_KEY = "SUA_API_KEY"

# Cabeçalhos unificados para todas as requisições à API do MISP
MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Configuração de Logging
logging.basicConfig(
    filename='/var/ossec/integrations/misp_hash.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.WARNING
)

# Configuração do Socket do Wazuh
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f"{pwd}/queue/sockets/queue"

# --- Fim da Configuração ---


def allowlist(ip_str):
    """
    Verifica se um endereço IP pertence a uma lista de redes permitidas (allowlist).

    Args:
        ip_str: O endereço IP em formato de string.

    Returns:
        True se o IP estiver em uma das redes da lista, False caso contrário.
    """
    # Adicione aqui as redes confiáveis que devem ser ignoradas
    ranges = [
        ipaddress.IPv4Network("xxx.xxx.xxx.xxx/24"),
        ipaddress.IPv4Network("xxx.xxx.xxx.xxx/24"),
    ]
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        return any(ip_obj in network for network in ranges)
    except ipaddress.AddressValueError:
        logging.warning(f"O valor '{ip_str}' não é um endereço IPv4 válido.")
        return False


def verificar_hash_parallel(hash_usuario, base_url, headers):
    """
    Verifica se um hash existe em qualquer warninglist do MISP usando paralelismo.
    Para no primeiro match encontrado.

    Args:
        hash_usuario: O hash a ser verificado.
        base_url: A URL base para o endpoint de warninglists (ex: https://misp/warninglists).
        headers: O dicionário de cabeçalhos para a requisição.

    Returns:
        True se o hash for encontrado, False caso contrário.
    """
    try:
        response = requests.get(f"{base_url}/index.json", headers=headers, verify=MISP_VERIFY_SSL, timeout=10)
        if response.status_code != 200:
            logging.warning(f"Falha ao obter index das warninglists: {response.status_code}")
            return False

        warninglists_data = response.json()
        if "Warninglists" not in warninglists_data:
            logging.warning(f"Formato inesperado no index.json das warninglists: {warninglists_data}")
            return False

        warninglist_ids = [w["Warninglist"]["id"] for w in warninglists_data["Warninglists"]]

        def check_list(warninglist_id):
            url = f"{base_url}/view/{warninglist_id}.json"
            try:
                list_response = requests.get(url, headers=headers, verify=MISP_VERIFY_SSL, timeout=10)
                if list_response.status_code != 200:
                    logging.warning(f"Falha ao obter warninglist {warninglist_id}: {list_response.status_code}")
                    return False

                list_data = list_response.json()
                if "Warninglist" not in list_data or "WarninglistEntry" not in list_data["Warninglist"]:
                    logging.warning(f"Formato inesperado na warninglist {warninglist_id}")
                    return False

                for entrada in list_data["Warninglist"]["WarninglistEntry"]:
                    if entrada["value"] == hash_usuario:
                        logging.warning(f"Hash {hash_usuario} encontrado na warninglist {warninglist_id}")
                        return True
                return False
            except Exception as e:
                logging.warning(f"Erro ao verificar warninglist {warninglist_id}: {e}")
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_id = {executor.submit(check_list, wid): wid for wid in warninglist_ids}
            for future in concurrent.futures.as_completed(future_to_id):
                if future.result():
                    executor.shutdown(cancel_futures=True)
                    return True

    except Exception as e:
        logging.warning(f"Erro ao obter ou processar warninglists: {e}")
    return False


def send_event(msg, agent=None):
    """ Envia um evento para o socket de análise do Wazuh. """
    if not agent or agent["id"] == "000":
        string = f"1:misp:{json.dumps(msg)}"
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"],
            agent["name"],
            agent.get("ip", "any"),
            json.dumps(msg),
        )
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        logging.warning(f"Erro ao enviar evento para o socket do Wazuh: {e}")


# --- Início do Fluxo Principal (Main Flow) ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.warning("Erro: Arquivo de alerta não fornecido.")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except Exception as e:
        logging.warning(f"Erro ao ler ou decodificar o arquivo de alerta: {e}")
        sys.exit(1)

    # Filtro 1: Ignorar alertas de agentes em redes confiáveis (Allowlist de IP)
    agent_ip = alert.get('agent', {}).get('ip')
    if agent_ip and agent_ip != "any":
        if allowlist(agent_ip):
            logging.warning(f"IP do agente {agent_ip} está na allowlist. Ignorando alerta.")
            sys.exit(0)

    # Filtragem 2: Ignorar regras específicas e alertas sem hash
    try:
        rule_id = alert.get('rule', {}).get('id')
        if rule_id in ['651']:
            sys.exit(0)

        hash_value = alert.get('syscheck', {}).get('md5_after')
        if not hash_value:
            sys.exit(0)
    except (KeyError, TypeError):
        sys.exit(0)

    logging.warning(f"Processando hash: {hash_value} do agente: {agent_ip}")

    # Etapa 1: Verificar se o hash existe como atributo no MISP
    misp_search_url = f"{MISP_URL}/attributes/restSearch/value:{hash_value}"
    try:
        response = requests.get(misp_search_url, headers=MISP_HEADERS, verify=MISP_VERIFY_SSL, timeout=10)
        response.raise_for_status()
        misp_api_response = response.json()
        logging.warning(f"Resposta da busca de atributos: {json.dumps(misp_api_response)}")

    except requests.exceptions.RequestException as e:
        logging.warning(f"Erro de conexão com a API do MISP: {e}")
        alert_output = {"misp": {}, "integration": "misp", "misp": {"error": f"Connection Error to MISP API: {e}"}}
        send_event(alert_output, alert.get("agent"))
        sys.exit(1)

    # Etapa 2: Processar a resposta e verificar nas warninglists se necessário
    if misp_api_response.get("response", {}).get("Attribute"):
        logging.warning(f"Atributo encontrado para o hash: {hash_value}")

        # 2.1. Verificar se o hash está em alguma warninglist para evitar falsos positivos
        start_time = time.time()
        warninglist_url = f"{MISP_URL}/warninglists"
        if verificar_hash_parallel(hash_value, warninglist_url, MISP_HEADERS):
            logging.warning(f"Hash {hash_value} encontrado em uma warninglist. Ignorando.")
            print(f"Encontrado na warninglist {hash_value}")
        else:
            logging.warning(f"Hash {hash_value} NÃO encontrado em warninglists. Gerando alerta.")
            print(f"Nao encontrado na warninglist {hash_value}")

            # 2.2. Construir e enviar o alerta enriquecido para o Wazuh
            attr = misp_api_response["response"]["Attribute"][0]
            alert_output = {
                "misp": {
                    "source": {"description": alert.get("rule", {}).get("description")},
                    "event_id": attr.get("event_id"),
                    "category": attr.get("category"),
                    "value": attr.get("value"),
                    "type": attr.get("type"),
                    "event_info": attr.get("Event", {}).get("info")
                },
                "integration": "misp"
            }
            send_event(alert_output, alert.get("agent"))

        end_time = time.time()
        print(f"Tempo total de verificação: {end_time - start_time:.2f} segundos")

    else:
        logging.warning(f"Hash {hash_value} não encontrado nos atributos do MISP.")

    sys.exit(0)