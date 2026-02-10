# Subnet Calculator & Practice Tool

A desktop IPv4 subnetting application built for **network engineers, students, and practitioners** who want both accurate calculations and realistic hands-on practice.

This tool goes beyond basic subnet calculators by combining deterministic IPv4 math with **interactive practice modes** that reflect real-world design, allocation, and troubleshooting scenarios.

---

## Features

### Subnet Calculator
Enter any IPv4 address and CIDR prefix to instantly calculate:

- Network ID
- Netmask and wildcard mask
- First and last usable host
- Broadcast address
- Total and usable host counts
- Next adjacent network

---

### Hosts → CIDR Planner (+10% Padding)
Plan subnets from a capacity-first perspective:

- Input required host count
- Automatically applies **10% growth padding**
- Calculates:
  - Smallest valid CIDR prefix
  - Netmask
  - Total vs usable addresses
  - Example network allocation

Perfect for early-stage network design and capacity planning.

---

### Practice Mode 1: Core Subnetting
Reinforce fundamental subnetting skills:

- Randomly generated private-range IPv4 questions
- Manually calculate:
  - Network ID
  - First host
  - Last host
  - Broadcast
  - Next network
- Immediate answer validation with detailed feedback
- Optional solution reveal for guided learning

Ideal for exam prep and muscle-memory training.

---

### Practice Mode 2: Allocation Gap Fitting
Simulates real DHCP and IPAM-style allocation problems:

- View a sorted list of allocated subnets
- Given a candidate CIDR size, identify **the single valid gap** where it fits
- Enforces:
  - Non-overlapping allocations
  - Proper CIDR boundary alignment
- Only one correct answer per question

