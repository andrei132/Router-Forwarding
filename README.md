# Tema 1 Protocoale de Comunicatii

## Descriere
---
Program care poate fi rulat pe router. Router-ul are implementat forwarding, 
ICMP Protocol si ARP Protocol

## Dependinte
---
```bash
sudo apt install mininet openvswitch−testcontroller xterm python3 − pip
sudo cp /usr/bin/ovs−testcontroller /usr/bin/ovs−controller
sudo pip3 install scapy
sudo pip3 install pathlib
sudo pip3 install git+https://github.com/mininet/mininet.git
```
## Rulare teste automate
---
Sunt necesare drepturi de rulare pentru checker.py si check.sh
```bash
chmod +x checker.py check.sh
```
Pentru rulare:
```bash
./check.sh
```

## Rulare manuala a topologiei
---
Topologie:
```
h0 --(r-0)--|                                      |--(r-0)-- h2
            |                                      |
            |--- r0 --(rr-0-1)----(rr-0-1)-- r1 ---|
            |                                      |
h1 --(r-1)--|                                      |--(r-1)-- h3
unde :
    h0, h1, h2, h3 -> host
    r0, r1 -> router programat
    r-0, r-1, rr-0-1 -> interfete ale router-ului
```

Rulare topologie
```bash
sudo fuser -k 6653/tcp
sudo python3 ./topo.py
```
Se vor deschide 7 terminale, fiecare v-a avea denumirea in comformitate cu topologia descrisa mai sus. In ambele routere este necesar sa rulezi comanda averenta pentru fiecare router
```bash
./router rtable0.txt rr−0−1 r−0 r−1 # router 1
./router rtable1.txt rr−0−1 r−0 r−1 # router 2
```
## Preprocesare
---
Inainte de a primi un pachet, aloc si populez route tabel.
Apoi aloc un arp tabel, si ii setez lungiamea la 0

## Procesarea pachetului
---

- Extrag toate header-urile, salvez mac-ul si ip-ul de pe interfata 
care a venit pachetul. 
- Verific daca pachetul este destinat mie
- Verific daca e un pachet ICMP. In caz ca e il procesez.
- Verific daca e pachet ARP si il procesez in caz ca e.
- Verific daca TTL e inca valid, daca nu e trimit un pachet ICMP
de tipul ICMP_TIME_EXCEEDED
- Verific checksum-ul pachetului ICMP
- Actualizez header-ul prin decrementarea TTL si recalcularea
checksum-ului
- Daca e pachet IP il prelucrez

## Protocolul ARP
---

- ARP REQUEST
    - Incerc sa vad daca deja exista intrare in ARP tabel
    - Daca nu o adaug
    - Formez raspunsul si trimit pachetul ARP

- ARP REPLY
    - Verific daca intrarea exista, daca da nu are sens reply
    - Creez si adaug noua intrare si incerc sa trimit toate pachetele
    din coada
    - Trimit toate packetele, iar care nu se pot trimite se lasa in 
    coada

## Protocolul ICMP
---
- Verific checksum-ul din pachetul ICMP si trimit pachetul ICMP

## Procesul de dirijare
---
- Verific TTL si checksum, si le actualizez
- Daca nu exista o ruta pana la destinatie, trimit eraorea 
ICMP_DEST_UNREACH
- Extrag intrarea in ARP
    + Daca exista i-au setez mac-ul si interfata, si trimit pachetul
    + Daca nu adaug pachetul in coada, si formez un nou pachet
    pentru a afla intrarea in ARP

##  Longest Prefix Match eficient
---
Sortez descrescator la inceputul programului, si cand caut cu binary search 
nu ma opresc la prima aparitie ci continui, practic mereu se va tinde la maska 
cea mai mare

## Actualizarea checksum incremental
---
- Comform sursei https://tools.ietf.org/html/rfc1624 (ecuatia 4),
checksumul se poate calcula incremental dupa formula: 
old_checksum - ~(old_value - 1) - new_value

Drepturile de autor pe cerinta, topologie, checker le detine echipa Protocoale 
de Comunicatii 2021 - 2022 UPB

Codul scris pentru functionarea router-ului Girnet Andrei