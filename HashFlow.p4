/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Modified by Yuliang Li liyuliang001@gmail.com;
 */
#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/pktgen_headers.p4"

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/impl.p4"

/*
action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstip : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;        _drop;
        _drop;
    }
    size: 256;
}*/

control ingress {
/*	if (1 == measurement_meta.stage) {
		stage1();
	} else if (2 == measurement_meta.stage) {
		stage2();
	} else if (3 == measurement_meta.stage) {
		stage3();
	} else if (4 == measurement_meta.stage) {
		stage4();
	}
	apply(do_resubmit_t);*/
//	apply(ipv4_lpm);
	apply(forward);
}

control egress {
//    apply(send_frame);
}
control stage1 {
	apply(set_status_t_1);
	apply(process_flow_srcip_t_1);
	apply(process_flow_dstip_t_1);
	apply(process_flow_proto_t_1);
	apply(process_flow_srcport_t_1);
	apply(process_flow_dstport_t_1);
	apply(compare_t_1);
}

control stage2 {
	apply(set_status_t_2);
	apply(process_flow_srcip_t_2);
	apply(process_flow_dstip_t_2);
	apply(process_flow_proto_t_2);
	apply(process_flow_srcport_t_2);
	apply(process_flow_dstport_t_2);
	apply(compare_t_2) {
		read_pktcnt_2 {
			apply(set_flag_one_t);
			apply(update_min_two_t);
		}
	}
}
control stage3 {
	apply(set_status_t_3);
	apply(process_flow_srcip_t_3);
	apply(process_flow_dstip_t_3);
	apply(process_flow_proto_t_3);
	apply(process_flow_srcport_t_3);
	apply(process_flow_dstport_t_3);
	apply(compare_t_3) {
		read_pktcnt_3 {
			apply(set_flag_two_t);
			apply(update_min_three_t);
		}
	}
}
control stage4 {
	apply(digest_calc_t);
	apply(process_digest_t);
	apply(ancillary_compare_t) {
		incre_temp_pktcnt {
			apply(set_flag_three_t);	
			apply(set_promotion_flag_t);
		}
	}
}
//control stage5 {//promote the flow record
//	apply(set_status_t);
//	if (1 == measurement_meta.flow_table_no) {
//		apply(write_flow_srcip_t_1);
//		apply(write_flow_dstip_t_1);
//		apply(write_flow_proto_t_1);
//		apply(write_flow_srcport_t_1);
//		apply(write_flow_dstport_t_1);
//		apply(promote_flow_pktcnt_t_1);
//	} else if (1 == measurement_meta.flow_table_no) {
//		apply(write_flow_srcip_t_2);
//		apply(write_flow_dstip_t_2);
//		apply(write_flow_proto_t_2);
//		apply(write_flow_srcport_t_2);
//		apply(write_flow_dstport_t_2);
//		apply(promote_flow_pktcnt_t_2);
//	} else if (1 == measurement_meta.flow_table_no) {
//		apply(write_flow_srcip_t_3);
//		apply(write_flow_dstip_t_3);
//		apply(write_flow_proto_t_3);
//		apply(write_flow_srcport_t_3);
//		apply(write_flow_dstport_t_3);
//		apply(promote_flow_pktcnt_t_3);
//	}
//}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}


table forward {
    reads {
        ig_intr_md.ingress_port: exact;
    }
    actions {
        set_egr; nop;
    }
}
