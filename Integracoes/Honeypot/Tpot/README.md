
# 📘 Catálogo de Scripts
Este diretório documenta e organiza diferentes scripts utilizados para integração do honeypot com o MISP.
Cada seção abaixo descreve um script específico, incluindo objetivo, funcionamento e instruções de uso.

# 🛡️ Script (tpot_to_misp.py): Integração de Honeypot Tpot com MISP
Este script implementa uma integração entre o honeypot T-Pot e o MISP para:

🔍 Coletar automaticamente IPs maliciosos registrados no Elasticsearch do T-Pot
🧠 Enriquecer os indicadores com informações de país e porta alvo
📤 Enviar os dados para o AbuseIPDB e gerar eventos no MISP com os IoCs observados

## ⚙️ Funcionamento

### 📥 Entrada
O script se conecta ao Elasticsearch da stack T-Pot e coleta eventos das últimas 30 minutos. O IP do honeypot é utilizado como exceção para evitar auto-relato.

### 🔁 Processo
- Descobre o IP do container Elasticsearch via Docker
- Consulta o Elasticsearch por eventos recentes, ignorando o IP do próprio honeypot
- Extrai IP de origem, país e porta alvo
- Adiciona os dados como atributos em um evento MISP
- Aplica tags com país e porta no atributo
- Envia o IP ao AbuseIPDB com a categoria adequada
- Cria e publica o evento no MISP

## 📂 Estrutura e arquivos importantes

Arquivo                  | Função
-------------------------|---------------------------------------------------------
tpot-misp-report.py      | Script principal da integração
(blocklist não aplicável)| (Não há uso de bloqueio direto neste script)
(logs podem ser adicionados)| Caso deseje rastrear erros ou execuções

## 🔐 Configuração
Antes de usar, edite as seguintes variáveis no início do script:

- URL do MISP:
```python
misp_url = "https://SEUENDERECOMISP"
key = "<sua_api_key>"
```

- IP do honeypot (para ser excluído da análise):
```python
honey = "<ip_do_honeypot>"
```

- Chave da API do AbuseIPDB:
```python
abuse_key = "<sua_chave_api_abuseipdb>"
```

## 📦 Dependências
- Python 3
- Módulos:
  - pymisp
  - elasticsearch
  - requests
  - json
  - datetime
  - subprocess
  - docker

## 🚨 Notas
- Certifique-se de que o container do Elasticsearch esteja em execução no ambiente T-Pot
- O script ignora o IP configurado como sendo do honeypot para evitar falso positivo
- Os eventos no MISP são marcados com as tags `tlp:green` e `Honeypot`
- O Threat Level do evento é configurado como "High" (1)
- AbuseIPDB é usado para registrar os IPs observados (pode ser removido ou substituído)
- Considerar adicionar logging para auditoria e análise futura

## 📍 Caminhos padrão (sugestão)
Caminho                               | Descrição
--------------------------------------|--------------------------------------------
/opt/integrations/tpot-misp-report.py | Local sugerido para armazenar o script
/opt/integrations/logs/misp.log       | Log de atividades (opcional)

## 📧 Contato
Em caso de dúvidas, contribuições ou melhorias, abra uma issue ou envie um pull request.

Para adicionar um novo script a este repositório, siga o modelo acima: comece com um título indicando o nome do script e descreva seu funcionamento, arquivos envolvidos, dependências e configurações necessárias.
