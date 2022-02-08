# Cyber-Oracle
Versatile tool for purple teaming that can give vision on the netowk and hosts, it can help identifying any weakpoints that could be used by adversaries to compromise the infrastructure.

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

## Notes

* **The central monitor can be a great target for attacks because it has all the information an attacker would dream about, and some kind of honeypot can be used to catch/identify attacks, so you can focus on one place which is most probably to be attacked**

* **Currently Cyberoracle is not scalable, so in big networks one central monitor may not be able to handle big numbers of hosts, hence it is planned to add scaleability by allowing central monitors to be configured to feed their data to upstream central monitors to form a hierarchical tree-like structure, so central monitors may have different roles (sink/forward), but this feature will be implemented in the future**

Thanks for Roman Szydlowsky for inspiring me to start this project, and thanks for virustotal for giving me a free API key and malware samples for the development of this project.
