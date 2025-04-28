# Network Packet Sniffer

A lightweight Python-based network packet sniffer that captures and logs network traffic for analysis.  
This project is intended for educational purposes and helps you understand how packet sniffing works at a basic level.

## 📜 Features

- Capture network packets on a specified interface (e.g., Wi-Fi, Ethernet)
- Filter packets based on protocol (`arp`, `bootp`, `icmp`, or `all`)
- Limit the number of packets captured or capture for a specific duration
- Save captured packets to a log file for offline analysis
- Runs with administrative/root privileges
- Cross-platform support (Windows/Linux)

![Screenshot 2025-04-28 204100](https://github.com/user-attachments/assets/89d7c95c-fa1f-48d2-b77c-c7bb68175809)


## 🚀 How to Run

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2. **Install dependencies**:
    - Make sure you have **Python 3.x** installed.
    - Install `scapy`:
    ```bash
    pip install scapy
    ```
    - Make sure to install ncap installer.
![Screenshot 2025-04-28 203826](https://github.com/user-attachments/assets/2cc00257-abc8-4452-843b-f2df6b549137)

3. **Run the script** (with Admin/Root permissions):
    ```bash
    python networkPacket.py
    ```

4. **Follow the prompts**:
    - Enter the network interface (e.g., `Wi-Fi` or `Ethernet`)
    - Enter number of packets or duration
    - Choose protocol (ARP, BOOTP, ICMP, or ALL)
    - Provide a name for the output log file (e.g., `logFile.txt`)

5. **View the captured data**:
    - Open the generated log file to see the captured packet information.

## ⚡ Example Run
![Screenshot 2025-04-28 204220](https://github.com/user-attachments/assets/c5aa3fb5-bc2d-48bd-822e-e236ae96be48)

```bash
> python networkPacket.py
* Enter the interface: Wi-Fi
* Enter number of packets to capture: 10
* Enter number of seconds to run capture: 30
* Enter protocol to filter (arp | bootp | icmp | 0 for all): 0
* Enter the name for the log file: logFile.txt
