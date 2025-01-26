
# Wazuh - Kompleksowy System Monitorowania Bezpieczeństwa

## Spis treści
- [Wprowadzenie](#wprowadzenie)
- [Architektura](#architektura)
- [Instalacja i wdrożenie](#instalacja-i-wdrożenie)
- [Konfiguracja](#konfiguracja)
- [Monitorowanie i alerty](#monitorowanie-i-alerty)
- [Integracje](#integracje)
- [Zarządzanie i utrzymanie](#zarządzanie-i-utrzymanie)
- [Rozwiązywanie problemów](#rozwiązywanie-problemów)

## Wprowadzenie

### Czym jest Wazuh?
Wazuh to kompleksowa platforma bezpieczeństwa typu open-source, łącząca następujące funkcjonalności:

1. **SIEM (Security Information and Event Management)**
   - Centralne zarządzanie logami
   - Analiza zdarzeń bezpieczeństwa
   - Korelacja alertów
   - Długoterminowe przechowywanie danych

2. **XDR (Extended Detection and Response)**
   - Wykrywanie zagrożeń
   - Automatyczna reakcja na incydenty
   - Analiza behawioralna
   - Threat hunting

3. **HIDS (Host-based Intrusion Detection)**
   - Monitorowanie integralności plików
   - Wykrywanie rootkitów
   - Analiza logów systemowych
   - Audyt bezpieczeństwa

4. **SOAR (Security Orchestration, Automation and Response)**
   - Automatyzacja reakcji na zagrożenia
   - Orkiestracja procesów bezpieczeństwa
   - Integracja z zewnętrznymi narzędziami
   - Zarządzanie incydentami

### Kluczowe funkcje
1. **Monitorowanie bezpieczeństwa**
   - Ciągła analiza logów systemowych
   - Wykrywanie modyfikacji plików
   - Monitorowanie procesów i połączeń
   - Analiza podatności

2. **Compliance i audyt**
   - Zgodność z PCI DSS
   - Implementacja HIPAA
   - Standardy NIST
   - Wymagania GDPR

3. **Threat Intelligence**
   - Integracja z bazami zagrożeń
   - Analiza IoC (Indicators of Compromise)
   - Automatyczne blokowanie zagrożeń
   - Raporty bezpieczeństwa

## Architektura

### Komponenty systemu

1. **Wazuh Server**
   ```plain
   /var/ossec/
   ├── active-response/    # Skrypty reakcji
   ├── agentless/         # Monitoring bezagentowy
   ├── bin/               # Pliki binarne
   ├── etc/               # Konfiguracja
   ├── logs/              # Logi systemowe
   ├── queue/             # Kolejki danych
   ├── rules/             # Reguły detekcji
   ├── stats/             # Statystyki
   └── var/               # Zmienne dane
   ```

2. **Wazuh Agent**
   ```plain
   /var/ossec/
   ├── active-response/   # Lokalne skrypty reakcji
   ├── bin/              # Pliki binarne agenta
   ├── etc/              # Konfiguracja agenta
   ├── logs/             # Logi lokalne
   └── queue/            # Kolejki danych
   ```

3. **Indexer (OpenSearch)**
   - Indeksowanie danych
   - Wyszukiwanie
   - Analityka
   - Wizualizacje

### Przepływ danych
```mermaid
graph LR
    A[Agent] -->|Szyfrowanie| B[Server]
    B -->|Analiza| C[Rules Engine]
    C -->|Alerty| D[Indexer]
    D -->|Wizualizacja| E[Dashboard]
```

## Instalacja i wdrożenie

### Wymagania systemowe

1. **Serwer Wazuh**
   - CPU: 4 rdzenie
   - RAM: 8GB (min) / 16GB (zalecane)
   - Dysk: 50GB (min) / 100GB (zalecane)
   - OS: Ubuntu 22.04 LTS

2. **Agent Wazuh**
   - CPU: 2 rdzenie
   - RAM: 2GB
   - Dysk: 20GB
   - Wspierane OS: Linux, Windows, macOS

### Proces instalacji

1. **Przygotowanie systemu**
   ```bash
   # Aktualizacja systemu
   sudo apt update && sudo apt upgrade -y
   
   # Konfiguracja firewall
   sudo ufw allow 1514/tcp  # Komunikacja agent-server
   sudo ufw allow 1515/tcp  # Rejestracja agentów
   sudo ufw allow 443/tcp   # HTTPS dla UI
   ```

2. **Instalacja serwera**
   ```bash
   # Pobieranie i uruchomienie instalatora
   curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a

   # Weryfikacja instalacji
   sudo systemctl status wazuh-manager
   sudo systemctl status wazuh-indexer
   sudo systemctl status wazuh-dashboard
   ```

3. **Instalacja agenta**
   ```bash
   # Dla Ubuntu/Debian
   wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb
   sudo WAZUH_MANAGER='server_ip' WAZUH_AGENT_NAME='host_name' dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb
   
   # Dla RHEL/CentOS
   sudo WAZUH_MANAGER='server_ip' WAZUH_AGENT_NAME='host_name' yum install wazuh-agent
   ```

## Konfiguracja

### 1. Konfiguracja serwera
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>admin@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>wazuh@example.com</email_from>
  </global>

  <rules>
    <included>rules_config.xml</included>
    <included>pam_rules.xml</included>
    <included>sshd_rules.xml</included>
  </rules>

  <syscheck>
    <frequency>43200</frequency>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/var/www,/var/lib</directories>
  </syscheck>

  <rootcheck>
    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
  </rootcheck>
</ossec_config>
```

### 2. Konfiguracja agenta
```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <client>
    <server>
      <address>server_ip</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>

  <syscheck>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    
    <!-- Critical files -->
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin</directories>
    
    <!-- Ignored paths -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
  </syscheck>
</ossec_config>
```

### 3. Reguły detekcji
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="local,syslog,">
  <!-- SSH brute force detection -->
  <rule id="100001" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5710</if_matched_sid>
    <description>Multiple SSH authentication failures.</description>
    <mitre>
      <id>T1110</id>
      <id>T1021.004</id>
    </mitre>
  </rule>

  <!-- Critical file changes -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Critical file modification.</description>
    <group>critical,pci_dss_10.5.5,</group>
  </rule>
</group>
```

## Monitorowanie i alerty

### 1. System monitorowania plików (FIM)
```xml
<syscheck>
  <!-- Real-time monitoring -->
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
  
  <!-- Registry monitoring (Windows) -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  
  <!-- Ignore list -->
  <ignore type="sregex">.log$|.tmp$</ignore>
  
  <!-- Custom file properties -->
  <nodiff>/etc/ssl/private.key</nodiff>
  <skip_nfs>yes</skip_nfs>
</syscheck>
```

### 2. Active Response
```xml
<!-- Server configuration -->
<command>
  <name>firewall-block</name>
  <executable>firewall-block.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-block</command>
  <location>local</location>
  <rules_id>100001</rules_id>
  <timeout>600</timeout>
</active-response>
```

### 3. Alerty i powiadomienia
```json
{
  "integration": "slack",
  "alert_format": "json",
  "hook_url": "https://hooks.slack.com/services/your-webhook",
  "alert_level": 10,
  "rule_id": [
    "100001",
    "100002"
  ]
}
```

## Integracje

### 1. Virustotal
```yaml
integration: virustotal
api_key: "your_api_key"
alert_level: 7
rule_id:
  - "100100"
  - "100101"
```

### 2. Slack
```yaml
integration: slack
hook_url: "https://hooks.slack.com/services/your-webhook"
alert_format: "json"
level: 10
rule_id:
  - "100001"
  - "100002"
```

### 3. AWS CloudWatch
```yaml
integration: aws-cloudwatch
aws_region: "us-east-1"
aws_log_group: "wazuh-alerts"
aws_log_stream: "security-events"
alert_level: 10
```

## Zarządzanie i utrzymanie

### 1. Backup systemu
```bash
#!/bin/bash
BACKUP_DIR="/backup/wazuh"
DATE=$(date +%Y%m%d)

# Backup konfiguracji
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /var/ossec/etc/

# Backup reguł
cp -r /var/ossec/rules $BACKUP_DIR/rules_$DATE

# Backup bazy danych
curl -XPUT "https://localhost:9200/_snapshot/wazuh_backup/snapshot_$DATE?wait_for_completion=true"
```

### 2. Monitoring wydajności
```bash
#!/bin/bash
# Sprawdzanie zużycia zasobów
ps aux | grep ossec | awk '{print $2,$3,$4,$11}'
df -h /var/ossec
free -m

# Sprawdzanie statusu usług
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
```

## Rozwiązywanie problemów

### 1. Diagnostyka agenta
```bash
# Sprawdzenie statusu
sudo systemctl status wazuh-agent

# Sprawdzenie logów
tail -f /var/ossec/logs/ossec.log

# Test połączenia
netstat -tulpn | grep ossec

# Restart agenta
sudo systemctl restart wazuh-agent
```

### 2. Diagnostyka serwera
```bash
# Sprawdzenie statusu komponentów
/var/ossec/bin/ossec-control status

# Analiza logów
tail -f /var/ossec/logs/alerts/alerts.log

# Sprawdzenie reguł
/var/ossec/bin/ossec-logtest

# Weryfikacja konfiguracji
/var/ossec/bin/ossec-verify-rules
```

## Dobre praktyki

### 1. Bezpieczeństwo
- Regularna aktualizacja systemu
- Monitorowanie logów błędów
- Backup konfiguracji
- Rotacja kluczy dostępu

### 2. Wydajność
- Optymalizacja reguł
- Zarządzanie retencją logów
- Monitoring zasobów
- Planowanie pojemności

### 3. Monitorowanie
- Weryfikacja alertów
- Analiza false-positives
- Dostosowanie reguł
- Dokumentacja incydentów

## Przydatne linki
- [Dokumentacja Wazuh](https://documentation.wazuh.com)
- [GitHub Wazuh](https://github.com/wazuh)
- [Wazuh Blog](https://wazuh.com/blog)
- [Forum społeczności](https://groups.google.com/g/wazuh)
