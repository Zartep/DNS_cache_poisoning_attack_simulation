
# 🛡️ DNS Cache Poisoning Simulation  
### *Simulazione di attacco DNS Cache Poisoning e delle relative contromisure*

Questo progetto dimostra, in un ambiente completamente controllato tramite Docker, le vulnerabilità del protocollo DNS e l’efficacia di diverse tecniche di mitigazione contro attacchi di tipo **Kaminsky** e **DNS Spoofing**.

Il cuore dell’infrastruttura è un **DNS Resolver custom** sviluppato in Python, in grado di abilitare o disabilitare manualmente le difese per osservare con precisione il successo o il fallimento di un attacco.

---

## 📋 Indice
- [Architettura del Sistema](#-architettura-del-sistema)  
- [Tecnologie Utilizzate](#-tecnologie-utilizzate)  
- [Installazione e Avvio](#-installazione-e-avvio)  
- [Simulazione dell'Attacco](#️-simulazione-dellattacco)  
- [Misure di Sicurezza Implementate](#-misure-di-sicurezza-implementate)  
- [Analisi del Traffico](#-analisi-del-traffico)  
- [Screenshot della Vittima](#-screenshot-della-vittima)  
- [Disclaimer](#-disclaimer)

---

## 🏗 Architettura del Sistema

Il progetto utilizza **Docker Compose** per creare un ambiente virtualizzato e totalmente isolato nella rete privata `172.20.0.0/24`, così da evitare la fuoriuscita di traffico malevolo.

| Componente | Ruolo | IP | Descrizione |
|-----------|-------|----|-------------|
| **DNS Resolver** | Target | `172.20.0.2` | Server DNS custom (Python/Gevent), vittima dell’attacco |
| **Attacker** | Attaccante | `172.20.0.3` | Container Kali Linux con script Python/Scapy |
| **Auth Server** | Autorità | `172.20.0.4` | Autorevole per il dominio target |
| **Client/User** | Vittima | `172.20.0.5` | Client che effettua la query legittima |

---

## 🛠 Tecnologie Utilizzate

- **Python 3.9+** – per server DNS e script di attacco  
- **Docker & Docker Compose** – orchestrazione dell'infrastruttura  
- **Scapy** – creazione e iniezione di pacchetti DNS spoofati  
- **dnslib** – parsing e generazione di record DNS  
- **Gevent** – concorrenza ad alte prestazioni  
- **Tcpdump / Wireshark** – analisi pacchetti `.pcap`  

---

## 🚀 Installazione e Avvio

Clona la repository:

```bash
git clone https://github.com/Zartep/DNS_cache_poisoning_attack_simulation.git
cd DNS_cache_poisoning_attack_simulation
```

Avvia l’infrastruttura:

```bash
docker-compose up --build -d
```

Verifica lo stato dei container:

```bash
docker-compose ps
```

---

## ⚔️ Simulazione dell'Attacco

L’attacco sfrutta una **race condition**: l’attaccante inonda il resolver con risposte spoofate mentre questo aspetta quella reale dal server autoritativo.

Accedi al container dell’attaccante:

```bash
docker exec -it attacker_machine bash
```

Esegui lo script:

```bash
python3 exploit.py --target 172.20.0.2 --domain esempio.com
```

Lo script effettua un flood di pacchetti DNS falsificati cercando di indovinare:

- **Transaction ID (TXID)**  
- **Porta sorgente (Source Port)**  
- **Case randomization 0x20 (se attiva)**  

---

## 🛡️ Misure di Sicurezza Implementate

Il server DNS custom replica manualmente le difese normalmente integrate nei server come BIND9, per scopi didattici.

### 1. 🔐 Source Port Randomization  
La porta sorgente per le query in uscita viene scelta casualmente da un ampio range.  
➡️ **Aumenta drasticamente l’entropia** e rende l'indovinamento della porta molto più difficile.

---

### 2. 🔑 Randomizzazione del Transaction ID (TXID)  
Generazione **crittograficamente sicura** del campo Transaction ID a 16 bit.  
➡️ Riduce la probabilità di successo dell’attacco.

---

### 3. 🔡 DNS 0x20 Bit Encoding (Mixed Case)  
Implementazione del draft *“Use of Bit 0x20 in DNS Labels”*.  

Funzionamento:
- Il resolver invia la query con casing casuale (es. `WwW.eSeMpIo.CoM`).
- La risposta deve avere lo **stesso identico casing**.

➡️ L’attaccante deve indovinare *anche* il pattern di maiuscole/minuscole → attacco quasi impossibile.

---

## 🔍 Analisi del Traffico

È possibile catturare il traffico DNS durante l’attacco:

```bash
docker exec -it dns_resolver tcpdump -i eth0 -w /data/capture.pcap udp port 53
```

Il file `.pcap` può essere analizzato con **Wireshark** per verificare:

- Flood di pacchetti spoofati  
- Risposta legittima del server autoritativo  
- Presenza o meno di avvelenamento della cache  

---

## 📸 Screenshot della Vittima

Ecco cosa vede la vittima quando esegue `dig google.com` dopo l’avvenuto avvelenamento:

![dig output](./Screenshot_2025-11-23_172606.png)

---

## ⚠️ Disclaimer

Questo software è sviluppato **esclusivamente per scopi accademici e di ricerca**.  
L’uso degli script contro sistemi reali senza autorizzazione è **illegale**.  
L’autore non si assume alcuna responsabilità per un eventuale uso improprio.

---
