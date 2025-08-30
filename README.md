# Wazuh on Docker

## Overview

This forked "wazuh-docker" repository is aimed at provisioning with personal configurations.

Single-node deployment only at the moment.

Current version: v4.12.0

## Task

### Continuous

- Updating CDB lists
- Updating decoders
- Updating rules

### Done

- Configuration provisioning
    - CDB lists
    - Decoders
    - Rules
    - SCA policies
    - Dashboard
- Windows agent provisioning
    - Setup Sysmon
    - Setup YARA & rules
    - Enable PowerShell logs gathering
    - Provision ransomware active responses (through YARA, CDB lists & VirusTotal)
    - Hyper-V
- Linux agent provisioning
    - Sysmon
    - AppArmor
- MacOS agent provisioning
- VALHALLA YARA managed rule update through Github Action
- Environment file for credentials

### To-do

- YARA on Linux agents
- Provisioning for AIO setup
- API setup script
- Recommended SOAR workflows
- Dashboard provisioning
- Malware hash sample CDB lists update automation
- Velociraptor integration with SIGMA rules
- VALHALLA SIGMA managed rule update through Github Action

## Note

1. SCA policies serve as a second method for malware detection in case of a network problem or a flooded event queue, which could cause the Wazuh server to miss important information.

## How-to

### Single-node Wazuh Cluster

This deployment is defined in the `docker-compose.yml` file with a Wazuh manager, indexer and dashboard container. It can be deployed by following these steps: 

1. Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```
3) Start the environment with docker-compose:

- In the foreground:
```
$ docker-compose up
```
- In the background:
```
$ docker-compose up -d
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.


### Wazuh Agents

#### Windows

1. Install agent on the `windows` endpoint group.

2. Install [Microsoft Visual C++ 2015 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).

3. Download the `./single-node/config/wazuh_endpoint/windows/active-response` folder and place it in the same directory as the script.

4. Run the `./single-node/config/wazuh_endpoint/windows/agent_provisioning.ps1` script.

##### Hyper-V (Disabled by default)

1. Navigate to **Indexer management > Dev Tools**, run `GET _cat/indices/wazuh-alerts-*`.

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

8. Restart agent service

```
systemctl restart wazuh-agent
```

#### MacOS

1. Install agent on the `macos` endpoint group.

2. Restart agent service

```
/Library/Ossec/bin/wazuh-control restart
```

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
