# Wazuh on Docker

## Overview

This forked "wazuh-docker" repository is aimed at provisioning with personal configurations.

Single-node deployment only at the moment.

Current version: v4.14.0

## Task

### Continuous

- Updating CDB lists
- Updating decoders
- Updating rules
- Updating YARA rules
- Resolving conflict rule IDs

### Done

- Configuration provisioning:
    - CDB lists
    - Decoders
    - Rules
    - Active responses
    - SCA policies
    - Dashboards
    - Environment file for credentials
- API:
    - VirusTotal (Disabled by default)
- Windows agent group:
    - Sysmon
    - YARA
    - Enable PowerShell logs
    - VSS restore
    - Hyper-V (Disabled by default)
    - Admin By Request
- Linux agent group:
    - Sysmon
    - AppArmor
    - MariaDB
    - Docker
    - Rsyslog (Disabled by default)
    - Zeek
    - Tetragon
- Suricata agent group
- MacOS agent group
- Github Action:
    - VALHALLA YARA managed rule update
    - Checking for conflict rule ID
- Misc:
    - CMMC Compliance

### To-do

- SOAR provisioning (Shuffle)
- Separate this single doc file into many
- YARA on Linux agents
- Provisioning for AIO setup
- API setup script
- Recommended SOAR workflows
- Dashboard provisioning
- Malware hash sample CDB lists update automation
- Velociraptor integration with SIGMA rules
- VALHALLA SIGMA managed rule update through Github Action
- Linux agent provision script
- Notification channel (Not really a good to-do since SOAR pretty does this job better than a SIEM)

## Note

1. SCA policies serve as a second method for malware detection in case of a network problem or a flooded event queue, which could cause the Wazuh server to miss important information.

## How-to

### Setup

This deployment is defined in the `docker-compose.yml` file with a Wazuh manager, indexer and dashboard container. It can be deployed by following these steps: 

1) Check the current max_map_count and increase if it's below 262,144:
```
sysctl vm.max_map_count
echo "vm.max_map_count=262144" | tee -a /etc/sysctl.conf
systemctl reboot
sysctl vm.max_map_count
```

2) Initial setup:
```
git clone https://github.com/sakkarose/wazuh-docker.git
cd wazuh-docker/single-node/
docker compose -f generate-indexer-certs.yml run --rm generator
```

3) Credential preparation:
```
# Generate hash for each password (API, indexer, dashboard)
docker run --rm -ti wazuh/wazuh-indexer:4.13.0 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh

# Update hashed password for admin user (indexer) and kibanaserver (dashboard)
cd wazuh-docker/single-node
nano config/wazuh_indexer/internal_users.yml

# Update hashed password for API
nano config/wazuh_dashboard/wazuh.yml

# Update plain password
cp env.example .env
nano .env

# Start the environment with docker compose
docker compose up -d
```

4) Certificate setup:
```
docker exec -it single-node-wazuh.indexer-1 bash
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk

# Wait for 5 minutes 
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $CACERT -cert $CERT -key $KEY -p 9200 -icl
```

### Update

```
cd wazuh-docker/single-node
docker compose down
cd ../
git fetch

# In case there are files that don't exist on main branch
git stash push -u -m "Temporary stash of local environment changes"

# Only do this once if you updated your credential
git update-index --assume-unchanged ./single-node/config/wazuh_indexer/internal_users.yml
git update-index --assume-unchanged ./single-node/config/wazuh_dashboard/wazuh.yml

git pull
cd single-node
docker compose pull
docker compose up -d
```

### Wazuh Agents

#### Windows

1. Install agent on the `windows` endpoint group.

2. Install [Microsoft Visual C++ 2015 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).

3. Download the `./single-node/config/wazuh_endpoint/windows/active-response` folder and place it in the same directory as the script.

4. Run the `./single-node/config/wazuh_endpoint/windows/agent_provisioning.ps1` script.

##### Hyper-V (Disabled by default)

1. Update `/etc/filebeat/wazuh-template.json` with this part at the `data` section, under `properties`.

```
      "data": {
        "properties": {
          "hyper-v.free_gb": {
            "type": "double"
          },
          "hyper-v.free_percent": {
            "type": "double"
          },
          "hyper-v.used_gb": {
            "type": "double"
          },
          "hyper-v.used_percent": {
            "type": "double"
          },
          "audit": {
            "properties": {
```

Navigate to **Indexer management > Dev Tools**, run `GET _cat/indices/wazuh-alerts-*`.

2. From the output, check for the date of the latest indices, then run `POST <RECENT_ALERTS_INDEX>/_doc` (.e.g: `POST wazuh-alerts-4.x-2025.04.28/_doc`).

3. Navigate to **Dashboard Management > Dashboard Management > Index patterns > wazuh-alerts-\***, click refresh button in the top-right corner.

4. In `./single-node/config/wazuh_endpoint/windows/agent.conf`, set <disabled> to no for the `hyper-v_metrics` command.

5. Check if Wazuh can receive Hyper-V metrics from your Windows agent(s) first, then navigate to **Dashboard Management > Dashboards Management > Saved objects**.

6. Click **Import**, tick `Request action on conflict` and select the file `hyper-v.ndjson` in `./config/wazuh_dashboard/custom`.

7. Click **Skip** on the **Overwrite index-pattern?** pop-up then click **Done**.

8. Navigate to **Dashboard Management > Dashboards Management > Index patterns**, select the `wazuh-alerts-*` index then click the refresh button in the top-right corner.

#### Linux

1. Install agent on the `linux` endpoint group.

2. Install Sysmon based on your agent operating system at [SysmonForLinux](https://github.com/microsoft/SysmonForLinux/blob/main/INSTALL.md).

3. Download the `./single-node/config/wazuh_endpoint/linux` folder

4. Setup the SysmonForLinux config file

```
sudo sysmon -accepteula -i
sudo sysmon -i ./single-node/config/wazuh_endpoint/linux/sysmon/sysmonforlinux-config.xml
```

5. Allow Sysmon to run at startup

```
sudo systemctl enable sysmon
sudo systemctl start sysmon
```

6. Copy file in `./linux/active-response/remove-threat.py` folder to `/var/ossec/active-response/bin/`

7. Set permission

```
chmod 750 /var/ossec/active-response/bin/remove-threat.py
chown root:wazuh /var/ossec/active-response/bin/remove-threat.py 
```

8. Copy files in `./linux/agent_config/policies/*` to `/var/ossec/etc/custom-sca-files/`

9. Set permission

```
chmod 660 /var/ossec/etc/custom-sca-files/*
chown wazuh:wazuh /var/ossec/etc/custom-sca-files/*
```

10. Restart agent service

```
systemctl restart wazuh-agent
```

##### Suricata

1. Setup Wazuh agent and add to `suricata & linux` groups.

2. Install [Suricata](https://docs.suricata.io/en/latest/install.html).

3. Configure suricata in `/etc/suricata/suricata.yaml`.

```
HOME_NET: "<INTERNAL_NET>"
EXTERNAL_NET: "any"

default-rule-path: /etc/suricata/rules
rule-files:
  - "*.rules"
# Global stats configuration
stats:
enabled: yes

# Linux high speed capture support
af-packet:
  - interface: eth0
```

4. Copy the `./suricata/local.rules` file to `/etc/suricata/rules/`.

5. Start suricata

```
systemctl enable suricata
systemctl restart suricata
```

##### Zeek

1. Install [Zeek](https://docs.zeek.org/en/master/install.html#) based on your agent operating system.

2. Set the packet capture interface in `/opt/zeek/etc/node.cfg`

```
[zeek]​
type=standalone​
host=localhost​
interface=eth0
```

3. Set the network subnet in `/opt/zeek/etc/networks.cfg`

```
# List of local networks in CIDR notation, optionally followed by a descriptive
# tag. Private address space defined by Zeek's Site::private_address_space set
# (see scripts/base/utils/site.zeek) is automatically considered local. You can
# disable this auto-inclusion by setting zeekctl's PrivateAddressSpaceIsLocal
# option to 0.
#
# Examples of valid prefixes:
#
# 1.2.3.0/24        Admin network
# 2607:f140::/32    Student network
<NETWORK_SUBNET>
```

4. Add the following line to enable JSON log generation in `/opt/zeek/share/zeek/site/local.zeek`

```
@load policy/tuning/json-logs.zeek
```

5. Do a configuration check and start Zeek

```
zeekctl check
zeekctl deploy

```

##### Tetragon

1. Install [Tetragon](https://tetragon.io/docs/installation/package/).

2. Copy tracing policies from `./linux/tetragon/*.yaml` to `/etc/tetragon/tetragon.tp.d/` and restart the service. You can get more example policies at [there](https://github.com/cilium/tetragon/tree/main/examples).

##### MariaDB

1. Append the content from `./linux/mariadb/my.cnf` to `/etc/my.cnf`. Make sure the Wazuh agent is already installed.

2. Restart the database service

```
systemctl restart mariadb.service
```

##### Rsyslog

1. Search for comment `<!-- Rsyslog` in `wazuh_manager.conf`.

2. Fill in the `port, protocol, allowed-ips & local_ip` fields.

3. At the end of the block, move the `-->` to the end of the comment on top.

4. On endpoints, edit the `/etc/rsyslog.conf` file with Wazuh's IP and port.

```
# TCP
*.* action(type="omfwd" target="<WAZUH_SERVER_IP>" port="<PORT>" protocol="tcp")

# UDP
*.* action(type="omfwd" target="<WAZUH_SERVER_IP>" port="<PORT>")

# Specific log (the *.* part)
if $programname == 'cron' or $programname == 'crond' or $programname == 'crontab' then {
    action(type="omfwd" target="<WAZUH_SERVER_IP>" port="<PORT>" protocol="tcp")
 }
& ~
```

5. Enable and start Rsyslog

```
systemctl start rsyslog
systemctl enable rsyslog
```

#### MacOS

1. Install agent on the `macos` endpoint group.

2. Restart agent service

```
/Library/Ossec/bin/wazuh-control restart
```

#### Misc

##### CCMC Compliance - Account Brute Force

- Check Hyper-V setup (From step 5 to 8).

##### VirusTotal API

1. Search for comment `<!-- VirusTotal Integration` in `wazuh_manager.conf`.

2. Fill in the `<api_key>`.

3. At the end of the API block, move the `-->` to the end of the comment on top.

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
