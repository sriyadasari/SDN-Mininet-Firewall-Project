SDN Firewall using POX and Mininet

Overview
This project implements a simple **SDN-based firewall** using the POX controller and Mininet. It blocks specific IP traffic and allows the rest using OpenFlow rules.

---

Topology

* 1 Switch (s1)
* 3 Hosts:

  * h1 → 10.0.0.1
  * h2 → 10.0.0.2
  * h3 → 10.0.0.3

---
Setup & Run

Start Controller
cd ~/pox
./pox.py log.level --DEBUG firewall

Run Mininet
sudo mn --topo single,3 --controller=remote --mac


---
Test Cases

Blocked::h1 ping h2
Allowed::h2 ping h3

---
Flow Table
sudo ovs-ofctl dump-flows s1

---
Performance

h2 iperf -s
h3 iperf -c 10.0.0.2

---
Result

* Selected IP traffic is **blocked**
* Other traffic is **allowed**
* Flow rules are installed dynamically

---
Conclusion

The project demonstrates how SDN enables **centralized control and flexible network security policies** using OpenFlow.

---

Author
Sriya Dasari
