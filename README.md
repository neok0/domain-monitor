# Domain Monitor
A free and easy domain monitor service.

## Overview
There are two main components included in this project.
- Domain Monitor
- Certificate Monitor

### Installation
create virtual environment and install dependencies
```
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r src/requirements
```

start up docker services
```
docker-compose up -d
```

create indicies first via
```
python3 src/initialize.py -c
```

A fast way to add new domain to monitor for is using the cmdline. However, it's propably easier to write a small script which uses the already existing generate methods.
```
python3 src/domain_monitor.py -d example.com
```

domain_monitor.sh and certificate_monitor.sh can be used as cronjob calls. For that please enter path to domain-monitor dir first.

### Domain Monitor
This repository is a simple and easy to use domain monitor for you branded domains.
It allows you to easy spot brand violations of possible malicious similar looking domains used e.g. in phishing attacks.
1. Use generate method in certifcate_watcher.py to add new domains.
2. Specify keywords for each domain to trigger alerts.
3. Create cronjob to fetch new registered domains and compare them against your watchlist.
4. Have a look at the generated alerts.



### Certificate Monitor
This tool can be used to monitor recently created TLS/SSL certificates.
It is similar to the Domain Monitor, however it uses the certificate stream provided by certstream.io.

### TODOs
- proper documentation
