/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 9
// H1 - 10.0.0.10
#define H1 0x0a00000a
// H2 - 10.0.1.10
#define H2 0x0a00010a
// H3 - 10.0.2.10
#define H3 0x0a00020a

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
                   TYPE_SRCROUTING: parse_srcRouting;
                   TYPE_IPV4: parse_ipv4;
                   default: accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
                   1: parse_ipv4;
                   default: parse_srcRouting;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>) hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action sroute_forward(bit<72> sourceRoute) {
	// Initializing bos with zeroes for all elements in srcRoutes
        hdr.srcRoutes[0].bos = 0; 
        hdr.srcRoutes[1].bos = 0; 
        hdr.srcRoutes[2].bos = 0; 
        hdr.srcRoutes[3].bos = 0; 
        hdr.srcRoutes[4].bos = 0; 
        hdr.srcRoutes[5].bos = 0; 
        hdr.srcRoutes[6].bos = 0; 
        hdr.srcRoutes[7].bos = 0; 
        hdr.srcRoutes[8].bos = 1;

	// Decoding values from table using bitmask technique
        hdr.srcRoutes[0].port = (bit<15>) ((sourceRoute & 0x0000000000000000ff));
        hdr.srcRoutes[1].port = (bit<15>) ((sourceRoute & 0x00000000000000ff00) >> (8 * 1));
        hdr.srcRoutes[2].port = (bit<15>) ((sourceRoute & 0x000000000000ff0000) >> (8 * 2));
        hdr.srcRoutes[3].port = (bit<15>) ((sourceRoute & 0x0000000000ff000000) >> (8 * 3));
        hdr.srcRoutes[4].port = (bit<15>) ((sourceRoute & 0x00000000ff00000000) >> (8 * 4));
        hdr.srcRoutes[5].port = (bit<15>) ((sourceRoute & 0x000000ff0000000000) >> (8 * 5));
        hdr.srcRoutes[6].port = (bit<15>) ((sourceRoute & 0x0000ff000000000000) >> (8 * 6));
        hdr.srcRoutes[7].port = (bit<15>) ((sourceRoute & 0x00ff00000000000000) >> (8 * 7));
        hdr.srcRoutes[8].port = (bit<15>) ((sourceRoute & 0xff0000000000000000) >> (8 * 8));

	// Setting the bos based on the next element port
	if (hdr.srcRoutes[1].port == 0) hdr.srcRoutes[0].bos = 1;
	if (hdr.srcRoutes[2].port == 0) hdr.srcRoutes[1].bos = 1;
	if (hdr.srcRoutes[3].port == 0) hdr.srcRoutes[2].bos = 1;
	if (hdr.srcRoutes[4].port == 0) hdr.srcRoutes[3].bos = 1;
	if (hdr.srcRoutes[5].port == 0) hdr.srcRoutes[4].bos = 1;
	if (hdr.srcRoutes[6].port == 0) hdr.srcRoutes[5].bos = 1;
	if (hdr.srcRoutes[7].port == 0) hdr.srcRoutes[6].bos = 1;
	if (hdr.srcRoutes[8].port == 0) hdr.srcRoutes[7].bos = 1;

	// The last element will always have bos 1
	hdr.srcRoutes[8].bos = 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table sroute_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            sroute_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
            // If it's H2, uses destination routing | else if it's etherType is srcRouting use source routing
	    if (hdr.ipv4.dstAddr == H2) {
  		ipv4_lpm.apply();

	    } else if (hdr.ethernet.etherType == TYPE_SRCROUTING) {
                // Check if it's an empty source routing header, then initialize using table values
	    	if (hdr.srcRoutes[0].port == 0 && hdr.srcRoutes[0].bos == 1) {
	 	    hdr.srcRoutes.push_front(2);
	       	    sroute_exact.apply();
	    	}	

		// Usual flow for source routing used in task 3
	    	if (hdr.srcRoutes[0].isValid()){
	    	    if (hdr.srcRoutes[0].bos == 1) {
	    	        srcRoute_finish();
	    	    }
		    srcRoute_nhop();
	    	    if (hdr.ipv4.isValid()){
	    	        update_ttl();
	    	    }
	    	}
	    }
	    else {
	    	drop();
	    } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
