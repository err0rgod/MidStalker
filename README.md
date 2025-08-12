# 🔍 Midstalker Analyzer by err0rgod

> **"Every packet hides a story. I give you the tools to decode it."**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.48.0+-red.svg)](https://streamlit.io/)
[![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-green.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **weapons-grade** PCAP (Packet Capture) analysis tool built for red teamers, cybersecurity researchers, and network analysts. This enhanced version provides comprehensive network traffic analysis with advanced visualization, geographic mapping, and security threat detection.

## 🌟 Features

### 🔥 Core Capabilities
- **Multi-Protocol Support**: Ethernet, IP, IPv6, TCP, UDP, ARP, ICMP, DNS, HTTP, HTTPS
- **Real-time Analysis**: Live packet processing and visualization
- **Geographic Mapping**: IP geolocation with interactive maps
- **Security Detection**: SQL injection, XSS, brute force, and malware patterns
- **Advanced Filtering**: Protocol, source, destination, and packet length filtering
- **Data Extraction**: HTTP, SMTP, POP3, IMAP, FTP, Telnet data reconstruction

### 📊 Analytics & Visualization
- **Protocol Statistics**: Comprehensive protocol distribution analysis
- **Traffic Flow Analysis**: Time-based traffic patterns and flow direction
- **Packet Length Distribution**: Statistical analysis of packet sizes
- **Interactive Charts**: Plotly, ECharts, and Folium-based visualizations
- **Geographic Analysis**: IP location mapping with traffic visualization

### 🛡️ Security Features
- **Attack Pattern Detection**: SQL injection, XSS, OS command injection signatures
- **Anomaly Detection**: Suspicious port activity and traffic patterns
- **Brute Force Detection**: Login failure analysis and attack identification
- **Malware Indicators**: Trojan and virus detection based on traffic patterns

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Git
- Internet connection (for GeoIP database)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/err0rgod/PCAP-Analyzer.git
   cd PCAP-Analyzer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:8501`

## 📖 Usage Guide

### 1. **Upload PCAP File**
- Go to the "Upload File" section
- Select a `.pcap` or `.cap` file from any folder
- The tool will automatically process and validate your file

### 2. **Raw Data Analysis**
- Navigate to "Raw Data & Filtering"
- View all packets in a searchable table
- Use advanced filters by protocol, IP, or packet length
- Export filtered data for further analysis

### 3. **Comprehensive Analytics**
- Visit the "Analysis" section for detailed insights
- Explore protocol statistics and traffic patterns
- Analyze inbound/outbound traffic flows
- Review security threat indicators

### 4. **Geographic Visualization**
- Check the "Geoplots" section for IP mapping
- View geographic distribution of network traffic
- Analyze global traffic patterns and connections

## 🛠️ Technical Architecture

### Core Components
```
PCAP-Analyzer/
├── app.py                 # Main Streamlit application
├── utils/
│   ├── pcap_decode.py     # Enhanced packet decoder
│   ├── data_extract.py    # Protocol data extraction
│   ├── flow_analyzer.py   # Traffic flow analysis
│   ├── proto_analyzer.py  # Protocol statistics
│   ├── except_info.py     # Security threat detection
│   ├── ipmap_tools.py     # Geographic mapping
│   └── protocol/          # Protocol definitions
├── requirements.txt       # Python dependencies
└── sample.pcap           # Sample data for testing
```

### Enhanced Features
- **English Documentation**: All Chinese comments translated to English
- **Improved Error Handling**: Robust file processing and validation
- **Better UI/UX**: Enhanced user interface with clear navigation
- **Comprehensive Logging**: Detailed error messages and debugging info

## 🔧 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `streamlit` | Latest | Web application framework |
| `scapy` | Latest | Packet manipulation and analysis |
| `plotly` | Latest | Interactive data visualization |
| `folium` | Latest | Geographic mapping |
| `geoip2` | Latest | IP geolocation database |
| `numpy` | Latest | Numerical computations |
| `pandas` | Latest | Data manipulation |

## 🎯 Use Cases

### 🔍 Network Forensics
- Investigate security incidents
- Analyze network breaches
- Reconstruct attack timelines
- Identify compromised systems

### 🛡️ Security Research
- Malware traffic analysis
- Attack pattern recognition
- Network vulnerability assessment
- Threat intelligence gathering

### 📊 Network Monitoring
- Traffic pattern analysis
- Performance optimization
- Bandwidth utilization
- Protocol distribution

### 🎓 Educational
- Network protocol learning
- Cybersecurity training
- Packet analysis practice
- Security tool development

## 🌐 About the Developer

**err0rgod** (Nirbhay Katiyar) - *10x Dev | IoT Hacker | Malware Dev | Red Teamer*

Electronics and cybersecurity enthusiast who creates high-impact, hacker-grade tools. This PCAP Analyzer is part of a mission to craft **next-gen offensive and defensive cybersecurity frameworks** — tools built for red teamers, researchers, and anyone who wants to see the raw truth hidden inside packets.

### Connect with err0rgod
- [**GitHub**](https://github.com/err0rgod) - Weapons-grade tools and experiments
- [**Medium**](https://err0rgod.medium.com/) - Cybersecurity insights and techniques
- [**LinkedIn**](https://www.linkedin.com/in/nirbhay-katiyar-904b86358/) - Professional networking
- [**Instagram**](https://www.instagram.com/err0rgod) - Personal brand

## 📝 Sample Data

The repository includes sample PCAP files for testing:
- `sample.pcap` - General network traffic
- `ftp-data.pcap` - FTP protocol analysis
- `ftp3.pcap` - FTP session data

## 🔄 Version History

### v2.0 (Current) - Enhanced by err0rgod
- ✅ Translated all Chinese comments to English
- ✅ Improved code documentation and structure
- ✅ Enhanced error handling and validation
- ✅ Added comprehensive protocol support
- ✅ Updated UI/UX with better navigation
- ✅ Added social media integration
- ✅ Improved file upload functionality

### v1.0 (Original) - by dj
- Basic PCAP analysis functionality
- Chinese language interface
- Core packet decoding capabilities

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Original Author**: dj (Chinese developer) - for the foundational PCAP analysis framework
- **Python Community**: For the excellent libraries and tools
- **Streamlit Team**: For the amazing web framework
- **Scapy Developers**: For the powerful packet manipulation library
- **Cybersecurity Community**: For continuous inspiration and feedback

## ⚠️ Disclaimer

This tool is designed for **legitimate cybersecurity research, network analysis, and educational purposes only**. Users are responsible for ensuring compliance with applicable laws and regulations. The developers are not responsible for any misuse of this software.

---

**Built with ❤️ by err0rgod for the cybersecurity community**

*"In the world of cybersecurity, knowledge is power, and packets are the truth."*
