#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para consultar atributos 'domain' (com flag IDS) dos últimos 6 meses no MISP,
verificar se estão ativos com pings em paralelo, filtrá-los com base em uma
LISTA ESPECÍFICA DE WARNING LISTS fornecida em um arquivo, e atualizar o Pi-hole.
"""

import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import requests
from dateutil.relativedelta import relativedelta
from pymisp import PyMISP


# --- Configurações do MISP ---
MISP_URL = 'https://SEU-SERVER-MISP'
MISP_KEY = 'SUA-API-KEY-MISP'
MISP_VERIFYCERT = True

# --- Configuração dos Arquivos Locais ---
BLOCKLIST_FILE_PATH = '/var/ossec/integrations/domain_blocklist.txt'
# Arquivo que conterá as URLs das warning lists a serem usadas.
WARNINGLIST_FILE_PATH = '/var/ossec/integrations/domain_warninglists.txt'

# --- Configuração de Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

def load_existing_blocklist(file_path):
    """
    Carrega os domínios já existentes na blocklist para um set.
    """
    if not os.path.exists(file_path):
        return set()
    try:
        with open(file_path, 'r') as f:
            domains = {line.split('#')[0].strip() for line in f if line.strip()}
        logging.info(f"Carregados {len(domains)} domínios da blocklist existente.")
        return domains
    except Exception as e:
        logging.error(f"Não foi possível ler a blocklist existente: {e}")
        return set()

def get_misp_domains(misp_client):
    """
    Consulta o MISP e retorna uma lista de strings de domínios ÚNICOS.
    """
    try:
        six_months_ago = datetime.now() - relativedelta(months=6)
        date_from = six_months_ago.strftime('%Y-%m-%d')
        logging.info(f"Consultando atributos 'domain' (com flag IDS e correlação ativada) desde {date_from}...")

        all_domains = []
        page = 1
        while True:
            logging.info(f"Buscando página {page} de resultados...")
            result = misp_client.search(
                controller='attributes', type_attribute='domain',
                date_from=date_from, to_ids=True, page=page, limit=10000,
                pythonify=True
            )

            if not result:
                logging.info("Não há mais páginas de resultados.")
                break

            for attr in result:
                if attr.disable_correlation:
                    continue
                all_domains.append(attr.value)
            page += 1

        logging.info(f"Encontrados {len(all_domains)} domínios acionáveis (incluindo duplicatas).")
        unique_domains = list(set(all_domains))
        logging.info(f"Reduzido para {len(unique_domains)} domínios únicos.")
        return unique_domains

    except Exception as e:
        logging.error(f"Erro ao consultar os atributos no MISP: {e}")
        return []

def ping_worker(domain):
    """Função de trabalho que pinga um único domínio."""
    is_windows = sys.platform.startswith('win')
    command_prefix = ['ping', '-n', '1', '-w', '2000'] if is_windows else ['ping', '-c', '1', '-W', '2']
    command = command_prefix + [domain]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=3)
        logging.info(f"  [+] Ping para '{domain}' bem-sucedido.")
        return domain
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, Exception):
        return None

def ping_check_domains(domains):
    """Executa pings em paralelo para os domínios."""
    if not domains: return []
    logging.info(f"Iniciando verificação de ping em PARALELO para {len(domains)} domínios...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_worker, domains)
    live_domains = [domain for domain in results if domain is not None]
    logging.info(f"Verificação de ping concluída. {len(live_domains)} domínios estão ativos.")
    return live_domains

def check_warning_lists(misp_client, domains):
    """
    Filtra domínios com base nas warning lists, verificando subdomínios.
    """
    try:
        logging.info(f"Verificando domínios contra as warning lists de {WARNINGLIST_FILE_PATH}...")
        if not os.path.exists(WARNINGLIST_FILE_PATH):            
            logging.error(f"ERRO CRÍTICO: Arquivo de warning lists não encontrado em '{WARNINGLIST_FILE_PATH}'.")
            logging.error("A execução foi interrompida para evitar o bloqueio de falsos positivos.")
            sys.exit(1) # Encerra o script com um código de erro.

        false_positives = set()
        with open(WARNINGLIST_FILE_PATH, 'r') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith('#'): continue
                try:
                    wl_id = url.split('/view/')[-1].split('.json')[0]
                    if not wl_id.isdigit(): continue

                    wl_content = misp_client.get_warninglist(wl_id)
                    entries = []
                    warninglist_data = wl_content.get('Warninglist', {})
                    if 'WarninglistEntry' in warninglist_data:
                        entries = [entry['value'] for entry in warninglist_data['WarninglistEntry'] if 'value' in entry]
                    elif 'list' in warninglist_data:
                        entries = warninglist_data['list']

                    if entries:
                        cleaned_entries = {entry.strip().lower() for entry in entries}
                        false_positives.update(cleaned_entries)
                except Exception as e:
                    logging.error(f"  -> Falha ao processar a URL {url}: {e}")

        logging.info(f"Total de {len(false_positives)} entradas de falsos positivos carregadas.")

        validated_domains = []
        ignored_count = 0

        for domain in domains:
            domain_to_check = domain.strip().lower()
            parts = domain_to_check.split('.')
            is_fp = False

            for i in range(len(parts) - 1):
                sub_domain = ".".join(parts[i:])
                if sub_domain in false_positives:
                    is_fp = True
                    break

            if is_fp:
                ignored_count += 1
            else:
                validated_domains.append(domain)

        logging.info(f"{ignored_count} domínio(s) foram identificados como falsos positivos e ignorados.")
        return validated_domains

    except Exception as e:
        logging.error(f"Erro crítico ao verificar as warning lists: {e}.")
        return domains

def update_pihole_list_and_gravity(preserved_domains, new_domains):
    """
    Combina os domínios, escreve a lista completa no arquivo local e aciona a
    atualização do Pi-hole, com logging detalhado.
    """
    final_domain_set = preserved_domains.union(new_domains)
    sorted_domains = sorted(list(final_domain_set))

    try:
        
        logging.info(f"Escrevendo {len(sorted_domains)} domínios únicos ({len(preserved_domains)} preservados + {len(new_domains)} novos) no arquivo {BLOCKLIST_FILE_PATH}...")

        with open(BLOCKLIST_FILE_PATH, 'w') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
        logging.info("Arquivo de lista de bloqueio atualizado com sucesso.")
    except Exception as e:
        logging.error(f"Falha ao escrever no arquivo de lista de bloqueio: {e}")
        return

    logging.info("Acionando 'pihole -g' para processar a lista atualizada...")
    try:
        command = ['pihole', '-g']
        result = subprocess.run(command, check=True, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        logging.info("Reconstrução da gravidade concluída.")
        for line in result.stdout.strip().split('\n'):
            if '[i] Number of' in line or '[✓] Done' in line:
                logging.info(f"[pihole] {line.strip()}")
    except Exception as e:
        logging.error(f"Falha ao executar 'pihole -g': {e}")

def main():
    """
    Função principal que orquestra o fluxo incremental.
    """
    logging.info("Iniciando script de sincronização incremental MISP -> Pi-hole.")

    existing_domains = load_existing_blocklist(BLOCKLIST_FILE_PATH)

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT, 'json')
        logging.info("Conectado ao MISP com sucesso.")
    except Exception as e:
        logging.error(f"Não foi possível conectar ao MISP. Erro: {e}")
        return

    misp_domains = get_misp_domains(misp)
    if not misp_domains:
        logging.info("Nenhum domínio encontrado no MISP. Mantendo a blocklist existente.")
        # Chamada modificada para passar um conjunto vazio de novos domínios.
        update_pihole_list_and_gravity(existing_domains, set())
        return

    new_candidate_domains = set(misp_domains) - existing_domains

    if not new_candidate_domains:
        logging.info("Nenhum domínio novo encontrado no MISP. A blocklist já está atualizada.")
        return

    logging.info(f"Encontrados {len(new_candidate_domains)} novos domínios candidatos para processamento.")

    validated_domains = check_warning_lists(misp, list(new_candidate_domains))
    live_new_domains = ping_check_domains(validated_domains)
   
    update_pihole_list_and_gravity(existing_domains, set(live_new_domains))

    logging.info("Script concluído.")

if __name__ == "__main__":

    main()

