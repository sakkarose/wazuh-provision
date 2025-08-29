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
- Windows agent provisioning
    - Setup Sysmon
    - Setup YARA & rules
    - Enable PowerShell logs gathering
    - Provision ransomware active responses (through YARA, CDB lists & VirusTotal)
- Linux agent provisioning
    - Sysmon
- MacOS agent provisioning
- YARA rule update thourgh Github Action
- Environment file for credentials

### To-do

- Hyper-V on Windows agent (WiP)
- Provisioning for AIO setup
- API setup script
- SOAR example workflows
- Dashboard provisioning
- Malware hash sample CDB lists automatic update
- Remove debug snippet on Github Action
- Velociraptor integration with SIGMA rules

## How-to

### Single-node Wazuh Cluster

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1. Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```
3) Start the environment with docker-compose:

- In the foregroud:
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

1. Install agent on the endpoint with default group being `windows`.

2. Install [Microsoft Visual C++ 2015 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).

3. Download the `./single-node/config/wazuh_endpoint/windows/active-response` folder and place it in the same directory as the script.

4. Run the `./single-node/config/wazuh_endpoint/windows/agent_provisioning.ps1` script.

#### Linux

1. Install agent on the endpoint with default group being `linux`.

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

1. Install agent on the endpoint with default group being `macos`.

2. Restart agent service

```
/Library/Ossec/bin/wazuh-control restart
```

## Note

1. SCA policies serve as a second method for malware detection in case of a network problem or a flooded event queue, which could cause the Wazuh server to miss important information.

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
