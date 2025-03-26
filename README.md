# Wazuh on Docker

## Overview

This forked "wazuh-docker" repository is aimed at provisioning with personal configurations.

Single-node deployment only at the moment.

Current version: v4.11.1

## Task

### Continuous

- Updating CDB lists
- Updating decoders
- Updating rules

### Done

- Configuration provisioning.
    - CDB lists
    - Decoders
    - Rules
- Windows agent provisioning.
    - Setup Sysmon
    - Setup YARA & rules
    - Enable PowerShell logs gathering
    - Provision ransomware active responses (through YARA, CDB lists & VirusTotal)
- YARA rule update thourgh Github Action.

### To-do

- Provisioning for AIO setup
- Shuffle worker provisioning.
- Shuffle example workflows.
- Grafana provisioning (Haven't decided between OpenSearch dashboard and Grafana).
- Malware hash sample CDB lists automatic update

## How-to

### Wazuh Cluster

### Wazuh Agents

#### Windows

1. Install agent on the endpoint with default group being **windows**.

2. Install [Microsoft Visual C++ 2015 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).

3. Download the `./active-response` folder and place it in the same directory as the script.

4. Run the `agent_provisioning.ps1` script.

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
