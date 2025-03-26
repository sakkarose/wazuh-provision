# Wazuh on Docker

## Overview

This forked "wazuh-docker" repository is aimed at provisioning with personal configurations (rules and active responses).

Single-node only at the moment.

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
- YARA rule update thourgh Github Action.

### To-do

- Shuffle worker provisioning.
- Shuffle example workflows.
- Grafana provisioning (Haven't decided between OpenSearch dashboard and Grafana).

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
