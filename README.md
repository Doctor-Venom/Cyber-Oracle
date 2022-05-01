# Cyber-Oracle
Versatile tool for purple teaming that can give vision in the network and on hosts, it can help identifying any weakpoints that could be used by adversaries to compromise the infrastructure.

[![Cyberoracle Video](https://img.youtube.com/vi/srhLgZ_P5HU/0.jpg)](https://www.youtube.com/watch?v=srhLgZ_P5HU)

## Cyber Oracle is made of 2 main parts:
1. The agents
: an agent is a single binary that is installed on individual hosts on the network in order to collect information about them and their surrounding environment and send that info to the central monitor
2. The Central Monitor
: receives the information collected by agents and stores it in a relational database to further analyze them to identify any security weakness or misconfiguration or any possible risk involved, and show them in a web app user interface to help security specialists to evaluate the environment and mitigate any unnecessary risks or weak points, and aid in incident response

## what information is collected from hosts?
- Host ID : composed of hostname, domain name, product id
- installed programs/apps/packages and their hashes
- running processes and their hashes
- dump of password hashes for all system users
- result of privelege escalation check script that checks various aspects of the system for a weakness that could lead to a privelege escalation ([PEASS-ng](https://github.com/carlospolop/PEASS-ng))
- result of exploit suggester script that shows if the system is outdated and vulnerable to any known exploits ([wesng](https://github.com/bitsadmin/wesng)/[linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester))
- general system information
- network information including MAC addresses of all network deevices, IP info, DNS cache, ARP cache, routing table, active ports
- nmap ping sweep scan result for all IP addresses on all connected netowrks ([nmap](https://nmap.org/))
- event logs
- scheduled tasks/cron jobs

## How To Use?
 NOTE: windows is preferred, because automation scripts (.bat) exist that facilitate the installation, support for linux will be added in the future.
- clone the repository
- make sure postgresql is installed, and create a database for the project
- update database information in `source_code/central_monitor/central_monitorsettings.py` (username, passowrd, created database name)
- install upx utility and make sure it is added to the PATH
- create a virutal environment (recommended) and install all python dependencies using `pip install -r requirements.txt` (requirements.txt is in `source_code` directory)
- run `source_code/host_agents/windows/MAKE.bat` to compile windows host agent binaries and prepare them to be downloaded (do the same for all other agent types when they will be implemented)
- run `source_code/central_monitor/_database_initialization.bat` to initialize the database
- run the command `python manage.py createsuperuser` to create a user that you will use to authenticate when using the central monitor web app
- run `python manage.py runserver <ip>:<port>` to start the web app
- run `python manage.py COP_server` to start the cyberoracle protocol master server
- open the app in a browser and go to settings page and set the settings that you need.
- you are now ready to go. download and install the agents on hosts and do whatever you please.

## Notes
* **This project requires alot of additional work and fine tuning, things are messed up.. but hey, at least it works (kind of)! and eventually everything will be fixed and organized.**

* **The central monitor can be a great target for attacks because it has all the information an attacker would dream about, and some kind of honeypot can be used to catch/identify attacks, so you can focus on one place which is most probably to be attacked**

* **Currently Cyberoracle is not scalable, so in big networks one central monitor may not be able to handle big numbers of hosts, hence it is planned to add scaleability by allowing central monitors to be configured to feed their data to upstream central monitors to form a hierarchical tree-like structure, so central monitors may have different roles (sink/forward), but this feature will be implemented in the future**

Thanks for Roman Szydlowsky for inspiring me to start this project, and thanks for virustotal for giving me a free API key and malware samples for the development of this project.

## TODOs
- [maybe] add PE-sieve to agents to scan the memory for shell codes
- add triggers for data collection procedures on agents
	- check for windows (https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
- log analysis on central monitor
	- collect logs with wincollect and rsyslog
	- check teler (https://github.com/kitabisa/teler)
- consider adding patch management
	- check patchman (https://github.com/furlongm/patchman)
	- check vFense (https://github.com/vFense/vFense)
- [maybe] add installation directory of agents to exclusion list of antivirus (https://stackoverflow.com/questions/40233123/windows-defender-add-exclusion-folder-programmatically)
- add filrewall rule to permit communication on port 51337, otherwise no inbound connections will be allowed from the central moninor
- fix the web shell to hosts
	- [maybe] make it open a real CMD instead of a web shell
	- make the shell come thorugh netcat with shell execution upon connection instead of piping through sockets
- add SOAR capabilities (can be used as action for the analytics or just be ran manually)
	- ability to isolate a host from the network
	- ability to hibernate/shutdown host 
	- ability to logout users and disable them
	- ability to kill processes
- add SIEM capabilities:
	- receive event logs and network flows and build analytics (check MITRE CAR)
	- add acions to analytics to trigger SOAR actions
- what to do with old data? (when some info is updated in database, it is being rewritten now)
- add vulnerability scanner
- gather threat intelligence feeds from defined STIX/TAXII feeds and use it for threat hunting using the collected data
- add ability to update the open source scripts/programs used on the central monitor with a single button
	- button for updating winpeas/wesng on central monitor
	- button for recompiling the agents
- add ability to download wordlists
- dockerize the app
	- arch linux container with all the packages needed (e.g. python3, hashcat)
	- postgres container
- encrypt the initial_host_settings.json because it contains sensitive data
- create the linux agent and linux agent installer/uninstaller
- create server agent for windwos
	- check this for Domain controllers (https://github.com/JPCERTCC/LogonTracer)
	- check (https://github.com/ahmedkhlief/APT-Hunter)
- create server agent for linux
- central monitor dashboard
- secure the communication with agents (apply crypto)
- create host information processing unit that processes info asynchronously
	- for that you can create a class with all utility functions
- finish the alerts_detail modal
- rework COP to be object oriented
- document all functions in the code
- rework datatables according to (https://gist.github.com/dkarchmer/37e421a2279a7300e994e9c86b56773a)
- add hash or something for each alert, if similar alert is generated, do coalescing (like in QRadar)
- add central monitor discovery in cyberoracle protocol https://stackoverflow.com/questions/21089268/python-service-discovery-advertise-a-service-across-a-local-network
- update the windows agent with the new scripts for data collection
