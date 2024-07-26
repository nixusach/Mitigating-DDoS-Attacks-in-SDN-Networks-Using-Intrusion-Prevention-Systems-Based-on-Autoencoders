# Mitigating DDoS Attacks in SDN Networks Using Intrusion Prevention Systems Based on Autoencoders

## Introduction

SDN (Software-Defined Networking) networks are known for centralizing control in a single intelligent device: the controller. This dependency means that if the controller is unavailable, the entire network goes down. This makes SDN networks vulnerable to availability attacks, especially DDoS (Distributed Denial of Service) attacks.

This project aims to implement an intrusion detection system in SDN networks to mitigate DDoS attacks. It consists of seven parts:
1. Configuring the environment
2. Creating the network and monitoring files
3. Collecting data
4. Building the autoencoder and machine learning models
5. Setting up flow rules to block malicious traffic
6. Developing a web interface to evaluate the performance of the solution

## Environment Configuration
The SDN network will be created on an Ubuntu OS using Mininet, with Ryu as the network controller. The `env_config` folder contains the necessary steps to install Ryu and Mininet, following the instructions at [Mininet Installation](https://mininet.org/download/) and [Ryu Documentation](https://ryu.readthedocs.io/en/latest/getting_started.html). It also includes the required packages for the entire project, such as data collection and the web interface.

## Creating the Network

There are two ways to create a Mininet network:

1. Develop a source code file named `topology.py` and execute it in the terminal using:
   ```bash
   sudo python3 topology.py

2. Use Miniedit, a graphical tool integrated with Mininet. To open Miniedit, run the following commands:
   ```bash
   cd mininet/mininet/examples
   sudo python3 miniedit.py

After designing your topology in Miniedit, click "File" and then "Export Level 2 Script" to obtain the Python script for your topology. If you encounter the error TypeError: can only concatenate str (not "int") to str while saving, resolve it by modifying line 2019 in the miniedit.py script from for widget, item in self.widgetToItem to for widget, item in self.widgetToItem.items().

## Data Collection

The objective of using the Ryu controller is its ability to program and control various aspects of our network using Python. We modify the Ryu library file `simple_monitor_13.py` to obtain the characteristics we want from the packets in our network. The available characteristics are described in OFPMatch at [OFPMatch Documentation](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html?highlight=OFPFlowMod#flow-match-structure).

We configure the file `simple_switch_13.py` to send the available characteristics using OFPMatch and save it as `simple_switch.py`. You can find this file in the `data_collection` folder. We also configure `simple_monitor_13.py` and save it as `monitor.py` to handle the received characteristics and save them in the file `flow1_mod`.

To collect the data, execute the monitor and topology using:

   ```bash
   sudo python3 monitor.py
   sudo python3 topology.py
   ```
Open the hosts' terminals. In the Mininet terminal, use the command:
   ```bash
   xterm h1 h2 h3 h4 h5 h6 h7 h8 h9
   ```
This will open all the host terminals. Then, in the terminals for h2 and h4, execute the files for the web server and the FTP server using the following commands:
   ```bash
   sudo python3 web-server.py
   sudo python3 ftp-server.py
```
For normal traffic, start by executing:
   ```bash
   sudo python3 create_files.py
   ```
This will create files for FTP operations. Next, execute the file traffic.py, which contains a loop of 40 sessions. Each session includes the execution of 3 functions:

- The first function sends a ping request with a random number of packets between 2 and 6 to a random IP address among the hosts.
- The second function performs an HTTP request to retrieve and download an item from the web server.
- The third function performs a random operation (download, upload, rename, delete) on an item in the shared resource of the FTP server.

For malicious traffic, we use the packages hping3 and Low Orbit Ion Cannon. The file attack.txt contains the commands used to perform DDoS attacks.
