# Wazuh
Simple wazuh for studies
# Wdrożenie Systemu Wazuh - Projekt Studencki

## Czym jest Wazuh?
Wazuh to kompleksowa platforma bezpieczeństwa typu open-source, która zapewnia:
- SIEM (Security Information and Event Management) - zarządzanie informacjami o bezpieczeństwie
- Wykrywanie włamań (IDS - Intrusion Detection System)
- Monitorowanie integralności plików
- Reagowanie na incydenty
- Zgodność z regulacjami (compliance)

### Jak działa monitorowanie?
1. Agent Wazuh zbiera dane z monitorowanego systemu:
   - Logi systemowe
   - Zmiany w plikach
   - Procesy i połączenia sieciowe
   - Podatności systemu

2. Dane są przesyłane do serwera Wazuh, gdzie są:
   - Analizowane pod kątem zagrożeń
   - Klasyfikowane według reguł
   - Wizualizowane w dashboardach
   - Zapisywane do bazy danych

3. Administrator otrzymuje:
   - Alerty o wykrytych zagrożeniach
   - Raporty zgodności
   - Statystyki bezpieczeństwa
   - Możliwość reakcji na incydenty

## Opis Projektu
Projekt obejmuje wdrożenie systemu monitorowania i bezpieczeństwa Wazuh w środowisku AWS. Wazuh to platforma open-source do wykrywania zagrożeń, monitorowania bezpieczeństwa i zgodności.

## Wykonane Kroki

### 1. Instalacja Serwera Wazuh
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

### 2. Instalacja Agenta
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb && sudo WAZUH_MANAGER='34.227.77.73' WAZUH_AGENT_NAME='ubuntu-serwer' dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb
```

### 3. Konfiguracja
- Otwarte porty w AWS: 1514, 1515 TCP
- Dostęp do interfejsu: https://[IP_SERWERA]
- Login: admin/admin (zalecana zmiana hasła)

Po instalacji można przeglądać dane w panelu Wazuh:
- Zdarzenia bezpieczeństwa
- Logi systemowe
- Alerty
- Statystyki

## Architektura
- Serwer Wazuh: 34.227.77.73
- Agent: Ubuntu Server

## Funkcjonalności
- Monitorowanie bezpieczeństwa systemów
- Wykrywanie zagrożeń
- Analiza logów
- Monitorowanie integralności plików
- Zgodność z regulacjami

## Wykorzystane Technologie
- AWS EC2
- Ubuntu 22.04 LTS
- Wazuh 4.7.5
- Security Groups AWS
