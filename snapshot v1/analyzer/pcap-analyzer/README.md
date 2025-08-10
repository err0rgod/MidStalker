# pcap-analyzer

## Overview
The pcap-analyzer is a web application designed to analyze packet capture (.pcap) files. It allows users to upload .pcap files, parse the packets, and visualize various statistics related to the network traffic.

## Features
- **File Upload**: Users can upload .pcap files for analysis.
- **Packet Parsing**: Utilizes Scapy to read and parse packets from the uploaded files.
- **Session State**: Maintains the uploaded file and parsed data in the session state for easy access.
- **Filtering**: Users can filter packets by protocol, source/destination IP, and packet length.
- **Statistics**: Displays protocol distribution, packet length statistics, and identifies top talkers in the network.
- **Visualization**: Provides visual representations of statistics using bar charts, pie charts, and line charts.
- **Geolocation**: Maps IP addresses to geographical locations using GeoIP and displays them on a map.
- **Raw Data View**: Allows users to view raw packet data with column filtering options.
- **Dashboard**: Combines all statistics and visualizations into a cohesive dashboard layout.

## Installation
To set up the project, follow these steps:

1. Clone the repository:
   ```
   git clone <repository-url>
   cd pcap-analyzer
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
To run the application, execute the following command:
```
streamlit run src/app.py
```

Open your web browser and navigate to `http://localhost:8501` to access the application.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.