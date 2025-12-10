

# **Nmap and Scapy Lab Documentation**

## **1. Objective**

This project documents the reproduction of Nmap and Scapy practical exercises. The goal was to perform host discovery, service enumeration, operating system detection, SMB scanning, packet crafting, packet sniffing, and ICMP traffic observation within an internal lab network. The exercises demonstrate foundational skills in reconnaissance, enumeration, and packet-level analysis.

---

## **2. Environment**

* Operating System: Kali Linux
* Tools: Nmap, Scapy, tcpdump
* Network Range: 10.6.6.0/24
* Target Host: 10.6.6.23
* Interface Used: br-internal / eth0
* Lab Type: Internal ParoCyber training network

---

# **Nmap Documentation**

## **1. Host Discovery**

```
nmap -sn 10.6.6.0/24
```

Performs a ping sweep to identify active hosts on the subnet.

---

## **2. Operating System Detection**

```
sudo nmap -O 10.6.6.23
```

Attempts OS fingerprinting using Nmap’s OS detection engine.

---

## **3. Port 21 Aggressive Service Scan**

```
nmap -p21 -sV -A -T4 10.6.6.23
```

Identifies the service running on port 21, detects version information, and performs aggressive scanning.

---

## **4. SMB Ports Scan (139 and 445)**

```
nmap -A -p139,445 10.6.6.23
```

Enumerates SMB services and gathers additional OS and network information.

---

## **5. SMB Share Enumeration with NSE Script**

```
nmap --script smb-enum-shares.nse -p445 10.6.6.23
```

Detects SMB shares available on the target system.

---

## **6. SMB Client Verification**

```
smbclient //10.6.6.23/print$ -N
exit
```

Used to manually verify SMB access and inspect the discovered share.

---

## **7. Supporting Network Context Commands**

```
ifconfig
ip route
cat /etc/resolv.conf
```

Displays interface information, route paths, and DNS resolver configuration.

---

## **8. Packet Capture with tcpdump**

```
sudo tcpdump -i eth0 -s 0 -w ladies.pcap
```

Captures all packets passing through the interface during the scans.
Stop capture:

```
ctrl + c
```

Verify file:

```
ls ladies.pcap
```

---

# **Scapy Documentation**

## **1. Starting Scapy as Root**

```
sudo su
scapy
```

---

## **2. Basic Packet Sniffing**

Start sniffing:

```
sniff()
```

Generate traffic in a new terminal:

```
ping google.com
```

Stop sniffing:

* `ctrl + c` on ping
* `ctrl + c` on Scapy

Store captured packets:

```
paro = _
paro.summary()
```

---

## **3. Interface-Specific Sniffing**

```
sniff(iface="br-internal")
```

Generate traffic:

```
ping 10.6.6.1/24
```

Visit internal page:

```
10.6.6.23
```

Stop sniffing:

```
ctrl + c
```

Store results:

```
paro2 = _
paro2.summary()
```

---

## **4. ICMP-Filtered Sniffing**

Capture only ICMP packets (five packets total):

```
sniff(iface="br-internal", filter="icmp", count=5)
```

Trigger ICMP:

```
ping 10.6.6.23
```

Stop terminals:

* `ctrl + c` ping
* `ctrl + c` Scapy

Store captured ICMP packets:

```
paro3 = _
paro3.summary()
```

Inspect a specific packet:

```
paro3[3]
```

---

# **Summary of Work**

The Nmap portion involved discovering active hosts, fingerprinting the target operating system, enumerating services, scanning SMB ports, and verifying SMB access. The Scapy portion demonstrated packet sniffing, interface-based capture, ICMP filtering, and packet inspection. Together, these exercises covered fundamental penetration testing reconnaissance and low-level packet analysis techniques used in real-world cybersecurity operations.

Added full Nmap and Scapy documentation

