
# 📘 Árvore de Tecnologias

Esta árvore organiza os diferentes scripts utilizados para integração com o MISP.  
Cada diretório listado abaixo contém scripts de integração entre soluções de cibersegurança e o MISP. Em cada um deles, são apresentados o objetivo da integração, seu funcionamento e as instruções de uso.

---

# 🛡️ Scripts publicados

| Arquivo | Tecnologia | Solução | Descrição | Autor |
|---------|------------|---------|-----------|-------|
| `custom-misp-ip.py`| SIEM | Wazuh | Bloqueio de IP Atacante | Rafael Pontes |
| `tpot_to_misp.py` | Honeypot | Tpot | Compartilhamento dos Atacantes | Bruno Odon|
| `custom-tpot-misp` | Honeypot | Tpot | Fork do `tpot_to_misp.py` adicionando tags da taxonomia ENISA e TLP além de portas e geolocalização de cada atributo | Rafael Pontes |
| `tpot-misp-hash.py` | Honeypot | Tpot | Extrai hashes de payloads maliciosos que atacantes utilizaram | Rafael Pontes |
| `custom-misp-hash.py`| SIEM | Wazuh | Consulta e classifica se Hash estiver listado no MISP | Rafael Pontes |
| `misp_pihole.py`| DNS Filter | Pi-Hole | Bloqueio de DNS Malicioso | Rafael Pontes |
