header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        proto : 8;
        hdrChecksum : 16;
        srcip : 32;
        dstip: 32;
    }
}

header_type tcp_t {
    fields {
        srcport : 16;
        dstport : 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 4;
        flags: 8;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}