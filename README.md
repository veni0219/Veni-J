# **Network Scanning Using Zenmap (Nmap GUI)**

## **📌 Project Overview**
This project demonstrates how to perform a basic network scan using **Zenmap**, the graphical user interface for Nmap. The goal is to discover active devices, identify open ports, detect running services, and understand how network reconnaissance works in cybersecurity.

---

## **📁 Contents**
- Introduction  
- Tools Used  
- Step-by-Step Procedure  
- Scan Results  
- Learning Outcomes  
- Description  

---

## **🛠 Tools Used**
- **Zenmap (Nmap GUI)**  
- **Windows Command Prompt / PowerShell** (for finding IP address)  

---

## **📡 Step-by-Step Procedure**

### **1. Check Your IP Address**
ipconfig

Note your **Wireless LAN Adapter** IPv4 address.  
Example:  
IPv4 Address: 192.168.29.164

This helps identify your network range.

---

### **2. Identify Network Range**
Take the first three octets of your IP:

192.168.29.0/24

This will be your scan target.

---

### **3. Open Zenmap**
Launch Zenmap from the Nmap installation.

---

### **4. Enter Target**
In the **Target** box, type:

192.168.29.0/24

(Replace with your network.)

---

### **5. Select Scan Profile**
Choose a suitable profile from the dropdown:
- Quick Scan  
- Quick Scan Plus  
- Intense Scan  

---

### **6. Start Scan**
Click **Scan** to begin scanning the network.

Zenmap will now:
- Discover hosts  
- Check open ports  
- Identify running services  
- Attempt OS detection  

---

### **7. View and Understand Results**
Zenmap provides:
- List of active devices  
- Open ports and services  
- Host details  
- Topology graph  
- Nmap command used  

---

## **📊 Scan Results Summary**
- Successfully scanned the network range.  
- Identified multiple active hosts within the LAN.  
- Detected common open ports such as 80 (HTTP), 443 (HTTPS), and 22 (SSH) depending on devices.  
- Generated visual network topology.  
- Demonstrated how network scanners work in real environments.

---

## **🎯 Learning Outcomes**
1. Understood how to check the local IP address.  
2. Learned to identify the correct network range for scanning.  
3. Performed network scanning using Zenmap.  
4. Interpreted scan results and port information.  
5. Gained basic knowledge of network reconnaissance and device discovery.

---

## **📘 Description**
This project focuses on performing a basic network scan using Zenmap, a GUI-based version of Nmap. The task helps understand how network discovery works, how devices respond to probing, and how cybersecurity professionals analyze networks to identify active hosts and services. Through this activity, you learn how scanning tools gather information, find open ports, and visualize network topology.

Open Command Prompt and type:

