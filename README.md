# NetFlowAnalyzer

NetFlowAnalyzer is a project designed to capture and analyze NetFlow data across a network using Python, Elasticsearch, and Wireshark. This repository contains scripts and configurations to facilitate network traffic monitoring and analysis.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Introduction

NetFlow Analyzer is a tool for network administrators and cybersecurity professionals to monitor, analyze, and visualize network traffic. By leveraging Python, Elasticsearch, and Wireshark, this project enables comprehensive NetFlow data analysis to identify network patterns, detect anomalies, and enhance security. 

## Features

- Capture NetFlow data from network devices.
- Store and index NetFlow data using Elasticsearch.
- Analyze and visualize network traffic patterns.
- Detect anomalies and potential security threats.
- Export analysis results in various formats.

## Prerequisites

Before using NetFlowAnalyzer, ensure you have the following prerequisites installed:

- Python 3.8 or higher
- Elasticsearch 8.x
- Wireshark 4.x
- pip (Python package installer)

## Installation

Follow these steps to install and set up NetFlowAnalyzer:

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/NetFlowAnalyzer.git
    cd NetFlowAnalyzer
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. Set up Elasticsearch:
    - Download and install Elasticsearch from the [official website](https://www.elastic.co/downloads/elasticsearch).
    - Start the Elasticsearch service.

## Usage

1. **Capture NetFlow Data**:
    - Configure your network devices to export NetFlow data to the system running NetFlowAnalyzer.
    - Use Wireshark to capture NetFlow packets.
    - Save the captured data in a pcap file.

2. **Analyze NetFlow Data**:
    - Modify and run the `main.py` script to process the captured data as needed.

3. **Index Data in Elasticsearch**:
    - Ensure Elasticsearch is running and the configurations in `netflow.ini` are correct.
    - Use the script to index the analyzed data into Elasticsearch.

4. **Visualize Data**:
    - Use Kibana (part of the Elastic Stack) to visualize the indexed NetFlow data.

## Configuration

The project contains configuration files to customize various aspects of data capture, analysis, and indexing. Modify these files as needed:

- `netflow.ini`: Configuration for paths, Elasticsearch, and logging.
    ```ini
    [Elasticsearch]
    URL = https://localhost:9200
    Username = elastic
    Password = your_password

    [logging]
    LOGGING_LEVEL = 30
    ```

## Main Script

The `main.py` script includes several key functions:

- `load_configuration()`: Reads configurations from the `netflow.ini` file.
    - This function loads the configuration settings from the `netflow.ini` file, making them available to other parts of the script.
  
- `setup_logging()`: Sets up logging based on the configuration.
    - This function initializes the logging settings as specified in the configuration file, allowing for appropriate logging levels and log file paths.
  
- `capture_packets(interface)`: Captures packets on a specified network interface.
    - Uses `pyshark` to capture network packets from the specified network interface.

- `process_packet(packet)`: Processes individual network packets.
    - Extracts and analyzes information from each captured packet, preparing it for further analysis or storage.

- `index_to_elasticsearch(data)`: Indexes data into Elasticsearch.
    - Takes the processed data and indexes it into an Elasticsearch instance, allowing for storage and subsequent querying.

- `main()`: The main function that ties everything together.
    - Coordinates the setup, packet capturing, processing, and indexing steps to perform comprehensive NetFlow analysis.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
