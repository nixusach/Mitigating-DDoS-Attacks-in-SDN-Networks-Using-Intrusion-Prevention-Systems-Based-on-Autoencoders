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
