
# 📘 Catálogo de Scripts

Este diretório documenta e organiza diferentes scripts utilizados para integração do Wazuh com o MISP.  
Cada seção abaixo descreve um script específico, incluindo objetivo, funcionamento e instruções de uso.

---

# 🛡️ Script (custom-misp-ip.py): Bloqueio de IP Atacante

Este script implementa uma **integração entre o Wazuh** e o **MISP** para:

- 🔍 Verificar automaticamente se o IP de origem de um alerta gerado pelo Wazuh está listado no MISP
- 🧠 Enviar metadados da ameaça como alerta enriquecido para o Wazuh
- 🚫 Adicionar o IP a uma **blocklist local** se ele estiver presente no MISP e for considerado malicioso

---

## ⚙️ Funcionamento

### 📥 Entrada
O script é executado automaticamente pelo Wazuh quando um alerta é gerado (`sys.argv[1]` aponta para o arquivo JSON do alerta).

### 🔁 Processo

1. Lê o alerta gerado pelo Wazuh (JSON)
2. Valida se o IP de origem (`srcip`) ou destino (`dstip`) é público
3. Consulta o **MISP** pela API usando o IP como valor
4. Se houver correspondência:
   - Adiciona o IP à `blocklist.txt`
   - Gera novo alerta enriquecido e envia ao Wazuh
5. Se o IP estiver em uma **faixa de allowlist**, é ignorado

---

## 📂 Estrutura e arquivos importantes

| Arquivo         | Função                                               |
|------------------|------------------------------------------------------|
| `misp.py`        | Script principal da integração                       |
| `blocklist.txt`  | Lista de IPs maliciosos identificados e bloqueados  |
| `misp.log`       | Log de atividades do script (alertas, erros, etc.)  |

---

## 🔐 Configuração

Antes de usar, edite as seguintes partes no script:

1. **URL da API do MISP**
   ```python
   misp_base_url = "https://SEUENDERECOMISP/attributes/restSearch/"
   ```

2. **API Key do MISP**
   ```python
   misp_api_auth_key = "Insira sua Auth Key do MISP aqui"
   ```

3. **Faixas de IPs permitidos (allowlist)**
   ```python
   ipaddress.IPv4Network("192.168.0.0/16")
   ```

---

## 📦 Dependências

- Python 3
- Módulos:
  - `requests`
  - `ipaddress`
  - `socket`
  - `json`
  - `logging`

---

## 🚨 Notas

- Dê as permissões corretas para o script
- O script ignora alertas com ID `651` e `100622`
- IPs privados (RFC1918) são filtrados para evitar falsos positivos
- Para que o IP seja bloqueado, ele precisa ser do tipo `"ip-src"` no MISP

---

## 📍 Caminhos padrão (no Wazuh)

| Caminho                                             | Descrição                                    |
|-----------------------------------------------------|----------------------------------------------|
| `/var/ossec/integrations/misp.py`                  | Local esperado do script                     |
| `/var/ossec/integrations/blocklist/blocklist.txt` | Arquivo onde os IPs maliciosos são registrados |
| `/var/ossec/integrations/misp.log`                | Log de atividades                            |

---

## 📧 Contato

Em caso de dúvidas, contribuições ou melhorias, abra uma **issue** ou envie um **pull request**.

---

> Para adicionar um novo script a este repositório, siga o modelo acima: comece com um título indicando o nome do script e descreva seu funcionamento, arquivos envolvidos, dependências e configurações necessárias.
