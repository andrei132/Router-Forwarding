/*Girnet Andrei 321CB*/
#include "queue.h"
#include "skel.h"

// Freestyle start here

#define QUEUE_SIZE 100
#define ROUTE_TABLE_SIZE 80000
#define ARP_TABEL_SIZE 100
#define ICMP_PROTOCOL 1
#define BROADCAST "FF:FF:FF:FF:FF:FF"

typedef struct ether_header eth_hdr;
typedef struct icmphdr icmp_hdr;
typedef struct arp_header arp_hdr;
typedef struct iphdr ip_hdr;
typedef struct route_table_entry route_table_entry;
typedef struct arp_entry arp_entry;
typedef struct in_addr in_addr;

/**
 * @brief Functie de comparare pentru sortare
 * 
 * @param a un element
 * @param b alt element
 * @return int pentru sortare dupa prefix, daca prefixul e acelasi
 * 				se sorteaza dupa mask
 */
int compare(const void * a, const void * b){
	
	route_table_entry ar = *(route_table_entry*)a;
	route_table_entry br = *(route_table_entry*)b;
	
	if(br.prefix == ar.prefix)
		return (br.mask - ar.mask);

	return (br.prefix - ar.prefix);
}

/**
 * @brief Intoarce header-ul de la  ICMP daca exista
 * 
 * @param msg mesajul de unde trebuie scos ICMP header
 * @return icmp_hdr* header-ul sau NULL daca nu exista
 */
icmp_hdr* icmp_parse(void* msg) {
	
	eth_hdr* ethhdr = (eth_hdr*)msg;
	ip_hdr* iphdr;

	// Daca este un pachet IP
	if(ntohs(ethhdr -> ether_type) == ETHERTYPE_IP){
		iphdr = (ip_hdr*)(msg + sizeof(eth_hdr));
		// Daca este un ICMP
		if(iphdr->protocol == ICMP_PROTOCOL)
			return (icmp_hdr*)(msg + sizeof(eth_hdr) + sizeof(ip_hdr));
		
		return NULL;
	}

	return NULL;
}

/**
 * @brief Intoarece headerul ARP daca exista
 * 
 * @param msg mesajul de unde trebuie scos ARP
 * @return arp_hdr* ARP header-ul sau NULL daca nu exista
 */
arp_hdr* arp_parse(void* msg){
	
	eth_hdr* ethhdr = (eth_hdr*)msg;

	// Pachet ARP
	if(ntohs(ethhdr -> ether_type) == ETHERTYPE_ARP)
		return (arp_hdr*)(msg + sizeof(eth_hdr));
	
	return NULL;
}

/**
 * @brief Setarea hedear-ului de ethernet cu valorile primite ca parametru
 * 
 * @param eth_hdr Header-ul ce trebuie setat
 * @param sha source
 * @param dha destination
 * @param type type
 */
void eth_hdr_set(eth_hdr *eth_hdr, uint8_t *sha, 
				uint8_t *dha, unsigned short type) {
	
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;

}

/**
 * @brief Seteaza header-ul de IP
 * 
 * @param iphdr Headerul ce trebuie setat
 * @param ver IPv4 -> 4
 * @param ihl Internet Header Length
 * @param tos type of service
 * @param protocol
 * @param tot_len 
 * @param id 
 * @param frag_off 
 * @param ttl ttl
 * @param daddr destination
 * @param saddr source
 */
void ip_hdr_set(ip_hdr* iphdr, unsigned int ver, unsigned int ihl, uint8_t tos,
				uint8_t protocol, uint16_t tot_len, uint16_t id, 
				uint16_t frag_off, uint8_t ttl, uint32_t daddr, uint32_t saddr){
	
	iphdr->version = ver;
	iphdr->ihl = ihl;
	iphdr->tos = tos;
	iphdr->protocol = protocol;
	iphdr->tot_len = tot_len;
	iphdr->id = id;
	iphdr->frag_off = frag_off;
	iphdr->ttl = ttl;
	iphdr->check = 0;
	iphdr->daddr = daddr;
	iphdr->saddr = saddr;
	iphdr->check = ip_checksum((uint8_t*)iphdr, sizeof(ip_hdr));
}

/**
 * @brief trimite un packet ICMP
 * 
 * @param daddr destination ip header
 * @param saddr source ip header
 * @param sha source ethernet header
 * @param dha destination ethernet header
 * @param type 
 * @param code 
 * @param interface Interfata pe care trebuie sa plece packet-ul
 * @param id 
 * @param seq 
 */
void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t* sha, uint8_t* dha,
			   u_int8_t type, u_int8_t code, int interface, int id, int seq){
	
	packet msg;
	eth_hdr ethhdr;
	ip_hdr iphdr;
	icmp_hdr icmphdr;

	icmphdr.type = type;
	icmphdr.code = code;
	icmphdr.checksum = 0;
	icmphdr.un.echo.id = id;
	icmphdr.un.echo.sequence = seq;
	icmphdr.checksum = icmp_checksum((uint16_t*)&icmphdr, sizeof(icmp_hdr));

	eth_hdr_set(&ethhdr, sha, dha, htons(ETHERTYPE_IP));
	ip_hdr_set(&iphdr, 4,5,0,IPPROTO_ICMP, htons(sizeof(ip_hdr) + sizeof(icmp_hdr)),
				htons(1),0,64,daddr,saddr);
	
	memcpy(msg.payload, &ethhdr, sizeof(eth_hdr));
	memcpy(msg.payload + sizeof(eth_hdr), &iphdr, sizeof(ip_hdr));
	memcpy(msg.payload + sizeof(eth_hdr) + sizeof(ip_hdr), &icmphdr, sizeof(icmp_hdr));

	msg.len = sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr);
	msg.interface = interface;

	send_packet(&msg);
}

/**
 * @brief Verifica daca e un packet activ si il trimite inapoi
 * 
 * @param icmphdr icmp header a packetului
 * @param ethhdr  ethernet header al packetului
 * @param iphdr  ip header a packetului
 * @param msg packet
 */
void icmp_echo(icmp_hdr* icmphdr, eth_hdr* ethhdr, ip_hdr* iphdr, packet* msg){

	uint16_t old_check_sum = icmphdr->checksum;
	icmphdr->checksum = 0;

	if(old_check_sum != icmp_checksum((uint16_t*)icmphdr, sizeof(icmp_hdr)))
		return;

	send_icmp(iphdr->saddr, iphdr->daddr, ethhdr->ether_dhost,
			  ethhdr->ether_shost, ICMP_ECHOREPLY, 
			  ICMP_ECHOREPLY, msg->interface, 0, 0);
}

/**
 * @brief Gaseste intrarea in ARP
 * 
 * @param arp_entry_table Toate adresele cunoscute
 * @param len numarul de adrese cunoscute
 * @param ip IP-ul cautat
 * @return arp_entry* Intrarea care a dat match
 */
arp_entry* get_entry(arp_entry* arp_entry_table, int len, uint32_t ip) {
	
	for (size_t i = 0; i < len; i++) {
		if (ip == arp_entry_table[i].ip)
			return &arp_entry_table[i];
	}

	return NULL;
}

/**
 * @brief Trimte un packet ARP
 * 
 * @param daddr destination
 * @param saddr source
 * @param ethhdr ethernet header
 * @param interface interfata pe care sa plece packet-ul
 * @param arp_op REQUEST/REPLY
 */
void send_arp(uint32_t daddr, uint32_t saddr, eth_hdr* ethhdr, 
				int interface, uint16_t arp_op){
	
	packet msg;
	arp_hdr* arphdr = calloc(1, sizeof(arp_hdr));

	arphdr->htype = htons(ARPHRD_ETHER);
	arphdr->ptype = htons(2048);
	arphdr->op = arp_op;
	arphdr->hlen = 6;
	arphdr->plen = 4;

	memcpy(arphdr->sha, ethhdr->ether_shost, 6);
	memcpy(arphdr->tha, ethhdr->ether_dhost, 6);

	arphdr->spa = saddr;
	arphdr->tpa = daddr;

	memset(msg.payload,0 ,MAX_LEN);
	memcpy(msg.payload, ethhdr, sizeof(eth_hdr));
	memcpy(msg.payload + sizeof(eth_hdr), arphdr, sizeof(arp_hdr));

	msg.len = sizeof(eth_hdr) + sizeof(arp_hdr);
	msg.interface = interface;

	send_packet(&msg);
}

/**
 * @brief Gaseste ruta in tabelul de rutare
 * 
 * @param route_table_entries Tabelul de rutare
 * @param route_table_len Lungimea tabelei de rutare
 * @param dest_ip Ip-ul cautat
 * @return route_table_entry* Intrarea care a dat match
 */
route_table_entry* get_best_route(route_table_entry* route_table_entries,
									int route_table_len, uint32_t dest_ip) {
	  	
	  	route_table_entry *bestMatch = NULL;
		int left = 0, right = route_table_len - 1;

		while(left <= right) {
			int mid = (left + right) / 2;

			// Continui, daca gasesc alta intrare, inseamna ca ea e mai buna
			if (route_table_entries[mid].prefix 
				== (dest_ip & route_table_entries[mid].mask)) {
				bestMatch = &route_table_entries[mid];
			}

			if (route_table_entries[mid].prefix 
				> (dest_ip & route_table_entries[mid].mask)) {
				left = mid + 1;
			} else {
				right = mid - 1;
			}
		}

	return bestMatch;

  }

/**
 * @brief Prelucreza un ARP REQUEST/REPLY
 * 
 * @param msg packet-ul
 * @param arphdr ARP header
 * @param ethhdr ethernet header
 * @param _arp_entry_table Adresa ARP table
 * @param len lungimea ARP table
 * @param be_sent_queue Coada cu packetele ce trebuie trimise
 * @param route_table_entries Tabela de rutare
 * @param route_table_len lungimea tabelei de rutare
 * @param mac 
 */
void arp_pak(packet* msg, arp_hdr* arphdr, eth_hdr* ethhdr, 
			arp_entry** _arp_entry_table, int* len, 
			queue* be_sent_queue, route_table_entry* route_table_entries, 
			int route_table_len, uint8_t* mac){
	
	arp_entry* arp_entry_table = *_arp_entry_table;

	// ARP request
	if(arphdr->op == htons(ARPOP_REQUEST)){
		// Incerc sa extrag intrarea
		arp_entry* arp_entry = get_entry(arp_entry_table, *len, arphdr->spa);
		
		// Intrarea nu exista
		if(!arp_entry){
			arp_entry_table[*len].ip = arphdr->spa;
			memcpy(arp_entry_table[*len].mac, arphdr->sha, ETH_ALEN);
			*len = *len + 1;
		}

		// Formez raspunsul
		eth_hdr tmp_ethhdr;
		tmp_ethhdr.ether_type = htons(ETHERTYPE_ARP);
		memcpy(tmp_ethhdr.ether_dhost, ethhdr -> ether_shost, ETH_ALEN);
		get_interface_mac(msg->interface, tmp_ethhdr.ether_shost);

		send_arp(arphdr->spa, arphdr->tpa, &tmp_ethhdr,
				 msg->interface,htons(ARPOP_REPLY));
		return;
	}

	// ARP reply
	if(arphdr->op == htons(ARPOP_REPLY)){
		// Deja exista
		if(get_entry(arp_entry_table, *len, arphdr->spa)) return; 

		// Noua intrare
		arp_entry_table[*len].ip = arphdr->spa;
		memcpy(arp_entry_table[*len].mac, ethhdr->ether_shost, ETH_ALEN);
		*len = *len + 1; 

		queue tmp_queue = queue_create();
		queue to_be_sent_queue = *be_sent_queue;

		// Trimit toate pachetele din coada
		while (!queue_empty(to_be_sent_queue)) {

			packet* msg = (packet*)queue_deq(to_be_sent_queue);
			ip_hdr* tmp_iphdr = (ip_hdr*)(((void*)msg->payload) + sizeof(eth_hdr));
			route_table_entry* best_route = get_best_route(route_table_entries,
															 route_table_len, 
															tmp_iphdr->daddr);

			if(best_route->next_hop == arphdr->spa){
				eth_hdr* tmp_ethhdr = (eth_hdr*) msg->payload;

				memcpy(tmp_ethhdr->ether_dhost, arp_entry_table[*len].mac, ETH_ALEN);
				memcpy(tmp_ethhdr->ether_shost, mac, ETH_ALEN);
				msg->interface = best_route->interface;

				send_packet(msg);
			} else{
				queue_enq(tmp_queue,msg);
			}
		}

		// Pachetele care nu s-au trimis se salveaza
		*be_sent_queue = tmp_queue;
	}
}

/**
 * @brief prelucreaza un packet 
 * 
 * @param msg packet-ul
 * @param iphdr ip header
 * @param ethhdr ethernet header
 * @param arp_entry_table ARP table
 * @param len lungimea ARP table
 * @param be_sent_queue coada cu packet-ele ce trebui trimise
 * @param route_table_entries Route table
 * @param route_table_len lungimea route table
 * @param mac 
 */
void ip_pak(packet* msg, ip_hdr* iphdr, eth_hdr* ethhdr, 
			arp_entry* arp_entry_table, int* len, queue* be_sent_queue, 
			route_table_entry* route_table_entries, int route_table_len,
			uint8_t* mac){

	route_table_entry* best_route = get_best_route(route_table_entries,
													route_table_len,
													iphdr->daddr);

	// Nu sa gasit intrarea in ROUTE tabel
	if(!best_route){
		send_icmp(iphdr->saddr, iphdr->daddr, ethhdr->ether_dhost, 
		ethhdr->ether_shost, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, 
		msg->interface,0 ,0);
		return;
	}

	arp_entry* arp_entry = get_entry(arp_entry_table, *len, 
									best_route->next_hop);

	// Intrarea exista in ARP tabel
	if(arp_entry){
		memcpy(ethhdr->ether_dhost, arp_entry->mac, ETH_ALEN);
		get_interface_mac(best_route->interface, ethhdr->ether_shost);
		msg->interface = best_route->interface;
		
		send_packet(msg);
		return;
	}

	// Nu exista intrarea in ARP table
	queue to_be_sent = *be_sent_queue;
	packet* _msg = calloc(1,sizeof(packet));
	eth_hdr tmp_ethhdr;
	in_addr inp_br;
	
	memcpy(_msg, msg, sizeof(packet));
	queue_enq(to_be_sent, _msg);

	tmp_ethhdr.ether_type = htons(ETHERTYPE_ARP);

	get_interface_mac(best_route->interface, tmp_ethhdr.ether_shost);
	hwaddr_aton(BROADCAST, tmp_ethhdr.ether_dhost);

	const char* ip_br = get_interface_ip(best_route->interface);	
	inet_aton(ip_br, &inp_br);

	send_arp(best_route->next_hop, inp_br.s_addr, &tmp_ethhdr, 
			best_route->interface, htons(ARPOP_REQUEST));
}

/**
 * @brief Verific mac prorpiu sau broadcast
 * 
 * @param ethhdr Headerul de ethernet
 * @param mac Mac propriu
 * @return int 1 daca e pachet pentru mine, 0 daca nu
 */
int check_my_packet(eth_hdr* ethhdr, uint8_t* mac){

	uint8_t brd[ETH_ALEN];
	hwaddr_aton(BROADCAST, brd);

	if(memcmp(brd, ethhdr->ether_dhost, ETH_ALEN) 
	|| memcmp(mac, ethhdr->ether_dhost, ETH_ALEN)) 
		return 0;
	return 1;

}

/**
 * @brief Calculeaza checksum incremental
 * 
 * @param old_checksum vechiul checksum
 * @param old_value vechea valoare a unui field oarecare pe 16 biti din header
 * @param new_value noua valoare a aceluiasi field pe 16 biti
 * @return uint16_t noul checksum
 */
uint16_t incremental_checksum(uint16_t old_checksum, uint16_t old_value, 
								uint16_t new_value) {

	/** 
	 * Implementare din RFC 1624 (https://tools.ietf.org/html/rfc1624)
	 * comform ecuatiei 4
	 */
	return old_checksum - ~(old_value - 1) - new_value;
}

// Freestyle ends here

int main(int argc, char *argv[]) {

	packet m;
	int rc;

	// Freestyle start here

	queue be_sent_queue = queue_create();
	route_table_entry* route_table = calloc(ROUTE_TABLE_SIZE, 
											sizeof(route_table_entry));
	int route_table_len = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_len, sizeof(route_table_entry), compare);

	arp_entry* arp_table = calloc(ARP_TABEL_SIZE, sizeof(arp_entry));
	int arp_len = 0;
	
	// Freestyle ends here

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Freestyle starts here

		// Extrag toate header-urile
		eth_hdr* ethhdr = (eth_hdr*)m.payload;
		icmp_hdr* icmphdr = icmp_parse(m.payload);
		arp_hdr* arphdr = arp_parse(m.payload);
		ip_hdr* iphdr = (ip_hdr*)(m.payload + sizeof(eth_hdr));
		const char* ip = get_interface_ip(m.interface);
		uint8_t mac[ETH_ALEN];
		in_addr inp;

		get_interface_mac(m.interface, mac);
		inet_aton(ip, &inp);

		// Verifica mac propriu sau broadcast
		if(check_my_packet(ethhdr, mac)) continue;

		// Este un pachet ICMP si este pentru mine
		if(icmphdr && inp.s_addr == iphdr->daddr && icmphdr->type == ICMP_ECHO){
			icmp_echo(icmphdr,ethhdr, iphdr, &m);
			continue;
		}

		// Este un packet ARP
		if(arphdr){
			arp_pak(&m,arphdr,ethhdr,&arp_table,&arp_len,&be_sent_queue,
					route_table,route_table_len,mac);
			continue;
		}
		
		// Verific TTL, daca nu e bun, trimit ICMP_TIME_EXCEEDED packet
		if(iphdr->ttl <= 1){
			send_icmp(iphdr->saddr, iphdr->daddr, ethhdr->ether_dhost, 
			ethhdr->ether_shost, ICMP_TIME_EXCEEDED, ICMP_NET_UNREACH,
			m.interface, 0, 0);
			continue;
		}
		
		uint16_t old_check_sum = iphdr->check;
		iphdr->check = 0;

		if(old_check_sum != ip_checksum((uint8_t*)iphdr,sizeof(ip_hdr))){
			continue;
		}

		iphdr->ttl--;
		iphdr->check = incremental_checksum(old_check_sum, iphdr->ttl + 1, 
											iphdr->ttl);

		if(ethhdr->ether_type == htons(ETHERTYPE_IP)){
			ip_pak(&m,iphdr,ethhdr,arp_table,&arp_len, &be_sent_queue, 
					route_table, route_table_len, mac);
		}

		// Freestyle ends here
	}

	return 0;
}
