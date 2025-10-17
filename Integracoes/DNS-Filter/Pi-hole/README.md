
# 📘 Catálogo de Scripts

Este diretório documenta e organiza diferentes scripts utilizados para integração do Pi-hole com o MISP.  
Cada seção abaixo descreve um script específico, incluindo objetivo, funcionamento e instruções de uso.

---

# 🛡️ Script (misp_pihole.py): Bloqueio de DNS Malicioso

Este script implementa uma **integração entre o Pi-hole** e o **MISP** para:

- 🔍 Verificar atributos do tipo dominio em eventos no MISP dos últimos 6 meses
- 🧠 Filtrar esses dominios com as warning lists para evitar falsos positivos, em seguida executar um ping para verificar se o domínio está ativo
- 🚫 Adicionar os domínios a uma **blocklist local** e roda um comando para o Pi-hole atualizar e ler o conteúdo da lista

---

## ⚙️ Funcionamento

### 📥 Entrada
O script deve ser executado na máquina onde o Pi-hole está instalado. O script pode ser executado manualmente ou programado pra execução automatica com o Cron.


## 📂 Estrutura e arquivos importantes

| Arquivo                    | Função                                                                |
|----------------------------|-----------------------------------------------------------------------|
| `misp_pihole.py`           | Script principal da integração                                        |
| `domain_blocklist.txt`     | Lista de domínios maliciosos identificados e bloqueados               |
| `domain_warninglists.txt`  | Lista de warning lists da sua instância MISP que o script irá checar  |

---

## 🔐 Configuração

Crie um arquivo chamado 'domain_warninglists.txt' e dentro dele coloque as warning lists que deverão ser usadas para filtragem
Exemplo:
 ```python
https://SEU-SERVER-MISP/warninglists/view/6

https://SEU-SERVER-MISP/warninglists/view/17

https://SEU-SERVER-MISP/warninglists/view/20
 ```

Antes de usar, edite as seguintes partes no script:

1. **URL da API do MISP**
   ```python
   MISP_URL = "https://SEU-SERVER-MISP"
   ```

2. **API Key do MISP**
   ```python
   MISP_KEY = "SUA-API-KEY-MISP"
   ```
---

## 📦 Dependências

- Python 3
- Módulos:
  - `requests`
  - `pymisp`
  - `sys`
  - `ipaddress`
  - `os`
  - `json`
  - `logging`
  - `subprocess`
  - `ThreadPoolExecutor`
  - `datetime`

---

## 🚨 Notas

- Dê as permissões corretas para o script
- O script gera a blocklist para ser usada pelo Pi-hole, mas o Pi-hole precisa ser configurado para ler a lista

---

## 📧 Contato

Em caso de dúvidas, contribuições ou melhorias, abra uma **issue** ou envie um **pull request**.

---

> Para adicionar um novo script a este repositório, siga o modelo acima: comece com um título indicando o nome do script e descreva seu funcionamento, arquivos envolvidos, dependências e configurações necessárias.

