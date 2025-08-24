# pcapana

A command-line tool for comprehensive network analysis from PCAP files. It provides detailed statistics on protocol usage, OSI layer distribution, open port communications, bandwidth consumption, and visited domains for network troubleshooting and security insights.

---

## 🚀 Features

`pcapana` dissects network traffic from a `.pcap` file and presents the data in a human-readable format. Its key features include:

* **📊 Protocol Statistics:** Get a breakdown of all protocols present in the capture, sorted by usage.
* **📡 OSI Layer Analysis:** View packet distribution across the OSI layers (L2, L3, L4, L5, L6, L7) for a high-level overview.
* **🌐 Visited Domains:** Identify the top visited domains from DNS, HTTP, and TLS traffic, ranked by frequency and traffic volume.
* **💻 Port Analysis:** Discover which local ports are communicating with which remote ports and services (e.g., HTTPS, SSH).
* **📈 Bandwidth Usage:** Analyze bandwidth consumption per IP address, showing sent, received, and total bytes.
* **📄 HTML Report:** Generate HTML report instead of just printing to terminal

---

## ⚙️ Installation

To install `pcapana`, simply use `pip`:

```bash
pip install pcapana
```
## 👨‍💻 Usage

The `pcapana` tool can be run with a simple command, with or without flags. If no flags are provided, it will run all available analyses by default.

### Running all analyses:

To run all available analyses on a PCAP file, provide the file path as the only argument:
```bash
pcapana path/to/your/file.pcap
```

### Running specific analyses:

You can use optional flags to run only the analyses you need.

|Flag | Description|
|----|---|
|`-p`, `--protocol` |Runs protocol statistics|
|  `-o`, `--osi` | Runs OSI analysis |
| `-po`, `--ports` | Runs port communication analysis |
| `-d`, `--domains` | Runs visited domains analysis |
| `-b`, `--bandwidth` | Runs bandwidth analysis |
|  `-r`,`--report` | Generates Detailed HTML Report of Analysis |

**Example:** To run only the port and protocol analysis and save it as a HTML report
```bash
pcapana -po -p -r path/to/your/file.pcap
```
