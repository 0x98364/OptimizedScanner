
# OptimizedScanner

Bash tool designed to optimize and order the results of a network scan.


### Prerequisites

This tool needs nmap and masscan instaled on the system, responder tool its optional for SMB tests.

### Run

This is an example for scan the nmap 1000 top ports TCP and UDP with masscan rate on 5000 on 192.168.1.0/24 network

```
./optiscanner.sh 192.168.1.0/24 1000 5000
```

## Authors

* **Matias Moreno** - *Initial work* - [0x98364](https://github.com/0x98364)

* **Belane** - *Thanks for giving me the idea* - [Belane](https://github.com/belane)
