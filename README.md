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
   ```
2. Use Miniedit, a graphical tool integrated with Mininet. To open Miniedit, run the following commands:
   ```bash
   cd mininet/mininet/examples
   sudo python3 miniedit.py
   ```
   After designing your topology in Miniedit, click "File" and then "Export Level 2 Script" to obtain the Python script for your topology. If you encounter the error `TypeError: can only concatenate str (not "int") to str` while saving, resolve it by modifying line 2019 in the miniedit.py script from`for widget, item in self.widgetToItem` to `for widget, item in self.widgetToItem.items()`.

## Data Collection

   The objective of using the Ryu controller is its ability to program and control various aspects of our network using Python. We modify the Ryu library file `simple_monitor_13.py` to obtain the characteristics we want from the packets in our network. The available characteristics are described in OFPMatch at [OFPMatch Documentation](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html?highlight=OFPFlowMod#flow-match-structure).

   We configure the file `simple_switch_13.py` to send the available characteristics using OFPMatch and save it as `simple_switch.py`. You can find this file in the `data collection` folder. We also configure `simple_monitor_13.py` and save it as `monitor.py` to handle the received characteristics and save them in the file `flow1_mod`.

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
This will create files for FTP operations. Next, execute the file `traffic.py`, which contains a loop of 40 sessions. Each session includes the execution of 3 functions:

- The first function sends a ping request with a random number of packets between 2 and 6 to a random IP address among the hosts.
- The second function performs an HTTP request to retrieve and download an item from the web server.
- The third function performs a random operation (download, upload, rename, delete) on an item in the shared resource of the FTP server.

For malicious traffic, we use the packages hping3 and Low Orbit Ion Cannon. The file `attack.txt` contains the commands used to perform DDoS attacks.

## Building the Autoencoder and Machine Learning Models

### Why Autoencoders?
An autoencoder is a type of artificial neural network used for learning efficient codings of input data. It consists of an encoder that compresses the input into a latent space representation and a decoder that reconstructs the input from this representation. The primary goal of an autoencoder is to minimize the difference between the input and the reconstructed output.

Autoencoders are popular for anomaly detection due to their ability to learn and model the normal patterns of the input data. When trained on normal (non-anomalous) data, an autoencoder becomes proficient at reconstructing these normal patterns. However, when it encounters anomalous data, it struggles to accurately reconstruct it, leading to a higher reconstruction error. By setting a threshold on this error, anomalies can be detected effectively.

### Data Cleaning
- **Outlier Analysis**: It is essential to remove outliers as they will affect the model's learning. Since we collected the data ourselves, we found no outliers.
- **Data Cleaning**: Remove null, NaN, and infinite values.
- **Feature Selection**: Remove unnecessary columns such as IP addresses, MAC addresses, etc., and select features using correlation analysis.
- **Grouping Rare Values**: We apply filtering on the `port_dst` column to remove rarely used ports, which are static ports assigned to a machine to communicate with specific ports such as 80 (HTTP), 443 (HTTPS), 22 (SSH), etc. Each rare port is replaced by the value 0.
- **Splitting the Data into Training, Validation, and Test Sets**: We split the data as follows:
  - 68% for training
  - 12% for validation
  - 20% for testing
- **Data Normalization**: After analyzing the data density, we chose to use the standard scaler for columns with a Gaussian distribution and MinMax scaler for others.

### Autoencoder Model
Our model has two symmetrical parts: an encoder that compresses the data and retains just the most relevant features, and a decoder that attempts to reconstruct the original input from these features. After selecting the best hyperparameters, our model is illustrated in the figure below:

We then calculated the minimum reconstruction error threshold (RMSE), determined from the error results at the end of training. For the test, we found an MSE of 0.03, resulting in an RMSE of 0.1732. However, when testing our model on the entire dataset, we found an MSE of 0.0301, giving an RMSE of 0.1736. This will be our reconstruction threshold. Any result with an RMSE error above 0.174 will be considered an anomaly.

### ML Model
In this section, we simulate six different algorithms (Random Forest, Decision Tree, XGBoost, Logistic Regression, Naive Bayes, KNN) and evaluate them using accuracy and error metrics to find the best model for our data.

## Setting Up Flow Rules to Block Malicious Traffic
The rules are presented in the image below:

## Web Interface
The final step of our implementation process is to develop a web interface. This interface has two objectives: to allow users to perform offline analyses of the data and to provide information on their network and the effectiveness of the intrusion detection system in real-time. It consists of a frontend (visual interface) and a backend (server and API).
