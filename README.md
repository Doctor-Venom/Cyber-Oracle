# Cyber-Oracle
Tool for monitoring windows and linux hosts on the local network for identifying any weakpoints that could be used by adversaries to gain access, escalate privileges or persist on the network.

## Cyber Oracle is made of 2 main parts:
1. The agents
: an agent is a single binary that is installed on individual hosts on the network in order to collect information about them and send it to the central monitor
2. The Central Monitor
: receives the information collected by agents and stores it in a relational database to further analyze them to identify any security weakness or misconfiguration or any possible risk involved, and show them in a web app user interface to help security specialists to evaluate the environment and mitigate any unnecessary risks or weak points, and aid in incident response

## what information is collected from hosts?
- Host ID : composed of hostname, domain name, product id
- installed programs/apps/packages and their hashes
- running processes and their hashes
- dump of password hashes for all system users
- result of privelege escalation check script that checks various aspects of the system for a weakness that could lead to a privelege escalation
- result of exploit suggester script that shows if the system is outdated and vulnerable to any known exploits
- general system information
- network information including MAC addresses of all network deevices, IP info, DNS cache, ARP cache, routing table, active ports
- nmap result for all hosts on all connected netowrks
- TODO: some kind of traffic analysis for the inbout/outbound traffic and send any suspicious stuff to the central monitor for further analysis

## Notes

* **The central monitor can be a great target for attacks because it has all the information an attacker would dream about, and some kind of honeypot can be used to catch/identify attacks, so you can focus on one place which is most probably to be attacked**

* **In big networks one central monitor may no be able to handle big numbers of hosts, hence central monitors can be configured to feed their data to upstream central monitors to form a hierarchical tree-like structure, but this feature will be implemented in the future**
