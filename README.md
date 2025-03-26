# Wazuh on Docker

## Overview

This forked "wazuh-docker" repository is aimed at provisioning with personal configurations (rules and active responses).

Single-node only at the moment.

Current version: v4.11.1

## Done

- Windows agent provisioning.
    - Setup Sysmon
    - Setup YARA & rules
    - Enable PowerShell logs gathering 

## To-do

- Github Action to run **download_yara_rules.py** & append it with **yara_rules_append.yar** daily.

## Credits

These Docker containers are based on:

* "deviantony" Dockerfiles, which can be found at [https://github.com/deviantony/docker-elk](https://github.com/deviantony/docker-elk)
* "xetus-oss" Dockerfiles, which can be found at [https://github.com/xetus-oss/docker-ossec-server](https://github.com/xetus-oss/docker-ossec-server)

and

* "wazuh" for the original development of "wazuh-docker".

## License and Copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
