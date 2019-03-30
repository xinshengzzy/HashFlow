// pre-compile commands:
#include "table_size.p4"
#include "tofino/intrinsic_metadata.p4"
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/pktgen_headers.p4"


#define MAIN_TABLE_IDX_WIDTH 32
#define ANCILLARY_TABLE_IDX_WIDTH 32
#define EMPTY 1
#define MATCHING 2
#define CONFLICT 3

// field lists:
field_list flow {
	ipv4.srcip;
	ipv4.dstip;
	ipv4.proto;
	tcp.srcport;
	tcp.dstport;
}

// field list calculations:
field_list_calculation main_hash_1 {
	input {
		flow;
	}
	algorithm: crc32;
	output_width: MAIN_TABLE_IDX_WIDTH;
}

field_list_calculation main_hash_2 {
	input {
		flow;
	}
	algorithm: crc32_extend;
	output_width: MAIN_TABLE_IDX_WIDTH;
}

field_list_calculation main_hash_3 {
	input {
		flow;
	}
	algorithm: crc32_lsb;
	output_width: MAIN_TABLE_IDX_WIDTH;
}

field_list_calculation ancillary_hash {
	input {
		flow;
	}
	algorithm: crc32_msb;
	output_width: ANCILLARY_TABLE_IDX_WIDTH;
}

field_list_calculation digest_hash {
	input {
		flow;
	}
	algorithm: identity;
	output_width: 8;
}

// headers:

header_type measurement_metadata_t {
	fields {
		srcip: 32;
		dstip: 32;
		prot: 8;
		srcport: 16;
		dstport: 16;
		pktcnt: 32;
		digest: 8;
		srcip_flag: 1;
		dstip_flag: 1;
		proto_flag: 1;
		srcport_flag: 1;
		dstport_flag: 1;
		digest_flag: 1;
		temp_pktcnt: 8;
		current_digest: 8;
		status: 2;	// whether the packet has been recorded
		flag: 32;
		flag_same_digest: 32;
		promotion_flag: 1;
		min_idx: 32;
		min_value: 32;
		m_idx_1: 32;
		m_idx_2: 32;
		m_idx_3: 32;
		a_idx: 32;
		temp: 32;
	//	total_pkt_cnt: 64;
	//	total_mem_access: 64;
	}
}

metadata measurement_metadata_t measurement_meta;

action set_promotion_flag() {
	modify_field(measurement_meta.promotion_flag, 1);
}
table set_promotion_flag_t {
	actions {set_promotion_flag;}
	default_action: set_promotion_flag;
}

// register for stage I:
register flow_srcip_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_srcip_one_alu {
	reg: flow_srcip_1;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.srcip;
	update_lo_2_predicate: ipv4.srcip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.srcip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcip_flag;
}
action process_flow_srcip_1() {
	flow_srcip_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_srcip_one_t {
	actions {process_flow_srcip_1;}
	default_action: process_flow_srcip_1;
}

register flow_dstip_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_dstip_one_alu {
	reg: flow_dstip_1;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.dstip;
	update_lo_2_predicate: ipv4.dstip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.dstip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_1() {
	flow_dstip_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_dstip_one_t {
	actions {process_flow_dstip_1;}
	default_action: process_flow_dstip_1;
}

register flow_proto_1 {
	width: 8;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_proto_one_alu {
	reg: flow_proto_1;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.proto;
	update_lo_2_predicate: ipv4.proto == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.proto == register_lo;
	output_value: 1;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_1() {
	flow_proto_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_proto_one_t {
	actions {process_flow_proto_1;}
	default_action: process_flow_proto_1;
}

register flow_srcport_1 {
	width: 16;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_srcport_one_alu {
	reg: flow_srcport_1;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.srcport;
	update_lo_2_predicate: tcp.srcport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.srcport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_1() {
	flow_srcport_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_srcport_one_t {
	actions {process_flow_srcport_1;}
	default_action: process_flow_srcport_1;
}

register flow_dstport_1 {
	width: 16;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_dstport_one_alu {
	reg: flow_dstport_1;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.dstport;
	update_lo_2_predicate: tcp.dstport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.dstport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_1() {
	flow_dstport_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_dstport_one_t {
	actions {process_flow_dstport_1;}
	default_action: process_flow_dstport_1;
}

register flow_pktcnt_1 {
	width: 32;	
	instance_count: SUB_TABLE_A_SIZE;
}
black_box stateful_alu record_flow_pktcnt_one_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo;
	output_value: alu_lo;
	output_dst: measurement_meta.min_value;
}
blackbox stateful_alu set_one_flow_pktcnt_one_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: 	1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu incre_flow_pktcnt_one_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
action set_one_flow_pktcnt_1() {
	set_one_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action incre_flow_pktcnt_1() {
	incre_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action find_matching_entry_1() {
	incre_flow_pktcnt_1();
	modify_field(measurement_meta.status, 1);
}
table compare_one_t {
	reads {
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.prot_flag: exact;
	}
	actions {
		find_matching_entry_1;
		update_min_1;
	}
	default_action: update_min_1;
}

// register for stage II:
register flow_srcip_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_srcip_two_alu {
	reg: flow_srcip_2;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.srcip;
	update_lo_2_predicate: ipv4.srcip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.srcip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcip_flag;
}
action process_flow_srcip_2() {
	flow_srcip_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_srcip_two_t {
	actions {process_flow_srcip_2;}
	default_action: process_flow_srcip_2;
}

register flow_dstip_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_dstip_two_alu {
	reg: flow_dstip_2;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.dstip;
	update_lo_2_predicate: ipv4.dstip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.dstip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_2() {
	flow_dstip_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_dstip_two_t {
	actions {process_flow_dstip_2;}
	default_action: process_flow_dstip_2;
}

register flow_proto_2 {
	width: 8;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_proto_two_alu {
	reg: flow_proto_2;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.proto;
	update_lo_2_predicate: ipv4.proto == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.proto == register_lo;
	output_value: 1;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_2() {
	flow_proto_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_proto_two_t {
	actions {process_flow_proto_2;}
	default_action: process_flow_proto_2;
}

register flow_srcport_2 {
	width: 16;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_srcport_two_alu {
	reg: flow_srcport_2;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.srcport;
	update_lo_2_predicate: tcp.srcport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.srcport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_2() {
	flow_srcport_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_srcport_two_t {
	actions {process_flow_srcport_2;}
	default_action: process_flow_srcport_2;
}

register flow_dstport_2 {
	width: 16;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_dstport_two_alu {
	reg: flow_dstport_2;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.dstport;
	update_lo_2_predicate: tcp.dstport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.dstport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_2() {
	flow_dstport_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_dstport_two_t {
	actions {process_flow_dstport_2;}
	default_action: process_flow_dstport_2;
}

register flow_pktcnt_2 {
	width: 32;	
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu set_one_flow_pktcnt_two_alu {
	reg: flow_pktcnt_2;
	update_lo_1_value: 	1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu incre_flow_pktcnt_two_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
black_box stateful_alu read_flow_pktcnt_two_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
action set_one_flow_pktcnt_2() {
	set_one_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action incre_flow_pktcnt() {
	incre_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action find_matching_entry_2() {
	incre_flow_pktcnt_2();
	modify_field(measurement_meta.status, 1);
}
action read_pktcnt_2() {
	read_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table compare_two_t {
	reads {
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.prot_flag: exact;
	}
	actions {
		find_matching_entry_2;
		read_pktcnt_2;
	}
	default_action: read_pktcnt_2;
}

// register for stage III:
register flow_srcip_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_srcip_three_alu {
	reg: flow_srcip_3;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.srcip;
	update_lo_2_predicate: ipv4.srcip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.srcip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcip_flag;
}
action process_flow_srcip_3() {
	flow_srcip_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_srcip_three_t {
	actions {process_flow_srcip_3;}
	default_action: process_flow_srcip_3;
}

register flow_dstip_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_dstip_three_alu {
	reg: flow_dstip_3;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.dstip;
	update_lo_2_predicate: ipv4.dstip == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.dstip == register_lo;
	output_value: 1;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_3() {
	flow_dstip_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_dstip_three_t {
	actions {process_flow_dstip_3;}
	default_action: process_flow_dstip_3;
}

register flow_proto_3 {
	width: 8;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_proto_three_alu {
	reg: flow_proto_3;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.proto;
	update_lo_2_predicate: ipv4.proto == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or ipv4.proto == register_lo;
	output_value: 1;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_3() {
	flow_proto_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_proto_three_t {
	actions {process_flow_proto_3;}
	default_action: process_flow_proto_3;
}

register flow_srcport_3 {
	width: 16;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_srcport_three_alu {
	reg: flow_srcport_3;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.srcport;
	update_lo_2_predicate: tcp.srcport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.srcport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_3() {
	flow_srcport_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_srcport_three_t {
	actions {process_flow_srcport_3;}
	default_action: process_flow_srcport_3;
}

register flow_dstport_3 {
	width: 16;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_dstport_three_alu {
	reg: flow_dstport_3;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: tcp.dstport;
	update_lo_2_predicate: tcp.dstport == register_lo; 
	update_lo_2_value: register_lo;
	output_predicate: 0 == register_lo or tcp.dstport == register_lo;
	output_value: 1;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_3() {
	flow_dstport_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_dstport_three_t {
	actions {process_flow_dstport_3;}
	default_action: process_flow_dstport_3;
}

register flow_pktcnt_3 {
	width: 32;	
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu set_one_flow_pktcnt_three_alu {
	reg: flow_pktcnt_3;
	update_lo_1_value: 	1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu incre_flow_pktcnt_three_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
black_box stateful_alu read_flow_pktcnt_two_alu {
	reg: flow_pktcnt_1;
	update_lo_1_value: register_lo;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
action set_one_flow_pktcnt_3() {
	set_one_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action incre_flow_pktcnt_3() {
	incre_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action find_matching_entry_3() {
	incre_flow_pktcnt_3();
	modify_field(measurement_meta.status, 1);
}
action read_pktcnt_3() {
	read_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table compare_three_t {
	reads {
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.prot_flag: exact;
	}
	actions {
		find_matching_entry_3;
		read_pktcnt_3;
	}
	default_action: read_pktcnt_3;
}

// register for stage IV:
register digest {
	width: 8;
	instance_count: ANCILLARY_TABLE_SIZE;
}
blackbox stateful_alu process_digest_alu {
	reg: digest;
	update_lo_1_value: measurement_meta.current_digest;
	output_predicate: 0 == register_lo or measurement_meta.current_digest == register_lo;
	output_value: 1;
	output_dst: measure_meta.digest_flag;
}
action process_digest() {
	process_digest_alu.execute_stateful_alu(measurement_meta.a_idx);
}
table process_digest_t {
	actions {process_digest;}
	default_action: process_digest;
}

register temp_pktcnt {
	width: 8;
	instance_count: ANCILLARY_TABLE_SIZE;
}
blackbox stateful_alu incre_temp_pktcnt_alu {
	reg: temp_pktcnt;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.temp_pktcnt;
}
blackbox stateful_alu set_one_temp_pktcnt_alu {
	reg: temp_pktcnt;
	update_lo_1_value: 1;
	output_value: alu_lo;
	output_dst: measurement_meta.temp_pktcnt;
}
action incre_temp_pktcnt() {
	incre_temp_pktcnt_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action set_one_temp_pktcnt() {
	set_one_temp_pktcnt_alu.execute_stateful_alu(measurement_meta.a_idx);
}
table ancilliary_compare_t {
	reads {measurement_meta.digest_flag;}
	actions {
		incre_temp_pktcnt;
		set_one_temp_pktcnt;
	}
	default_action: set_one_temp_pktcnt;
}


/*
register flow_ip_1 {
	width: 64;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_ip_one_alu {
	reg: flow_ip_1;
	condition_lo: ipv4.srcAddr == register_lo;
	condition_hi: ipv4.dstAddr == register_hi;
	update_lo_1_predicate: 0 == register_lo;
	update_lo_1_value: ipv4.srcAddr;
	update_lo_2_predicate: ipv4.srcAddr == register_lo; 
	update_lo_2_value: register_lo;
	update_hi_1_predicate: 0 == register_hi;
	update_hi_1_value: ipv4.dstAddr;
	update_hi_2_predicate: ipv4.dstAddr == register_hi;
	update_hi_2_value: register_hi;


	output_value: alu_lo;
	output_dst: measurement_meta.srcip;	  
}
register flow_ip_2 {
	width: 64;
	instance_count: SUB_TABLE_B_SIZE;
}
register flow_ip_3 {
	width: 64;
	instance_count: SUB_TABLE_C_SIZE;
}

blackbox stateful_alu flow_dstip_read_alu {
	reg: flow_ip;
	update_hi_1_value: register_hi;
	output_value: alu_hi;
	output_dst: measurement_meta.dstip;	  
}
blackbox stateful_alu flow_ip_write_alu {
	reg: flow_ip;
	update_lo_1_value: ipv4.srcAddr;
	update_hi_1_value: ipv4.dstAddr;
}
action read_srcip_1() {
	flow_srcip_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_srcip_read_alu.execute_stateful_alu_from_hash(main_hash_1);
}
action read_dstip_1() {
//	flow_dstip_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action write_ip_1() {
	flow_ip_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_ip_write_alu.execute_stateful_alu_from_hash(main_hash_1);
}
action read_srcip_2() {
//	flow_srcip_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_dstip_2() {
//	flow_dstip_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action write_ip_2() {
//	flow_ip_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_srcip_3() {
//	flow_srcip_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action read_dstip_3() {
//	flow_dstip_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action write_ip_3() {
//	flow_ip_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action promote_ip() {
//	flow_ip_write_alu.execute_stateful_alu(measurement_meta.min_idx);
}
table read_srcip_one_t {
	actions {
		read_srcip_1;
	}
//	default_action: read_srcip_1;
	size: 1;
}
table read_dstip_one_t {
	actions {
		read_dstip_1;
	}
//	default_action: read_dstip_1;
	size: 1;
}
table write_ip_one_t {
	actions {
		write_ip_1;
	}
//	default_action: write_ip_1;
	size: 1;
}
table read_srcip_two_t {
	actions {
		read_srcip_2;
	}
	default_action: read_srcip_2;
}
table read_dstip_two_t {
	actions {
		read_dstip_2;
	}
	default_action: read_dstip_2;
}
table write_ip_two_t {
	actions {
		write_ip_2;
	}
	default_action: write_ip_2;
}
table read_srcip_three_t {
	actions {
		read_srcip_3;
	}
	default_action: read_srcip_3;
}
table read_dstip_three_t {
	actions {
		read_dstip_3;
	}
	default_action: read_dstip_3;
}
table write_ip_three_t {
	actions {
		write_ip_3;
	}
	default_action: write_ip_3;
}
table promote_ip_t {
	actions {
		promote_ip;
	}
	default_action: promote_ip;
}

// register for protocol:
register flow_prot_1 {
	width: 8;
	instance_count: SUB_TABLE_A_SIZE;
}
register flow_prot_2 {
	width: 8;
	instance_count: SUB_TABLE_B_SIZE;
}
register flow_prot_3 {
	width: 8;
	instance_count: SUB_TABLE_C_SIZE;
}

blackbox stateful_alu flow_prot_read_alu {
	reg: flow_prot;
	output_value: register_lo;
	output_dst: measurement_meta.prot;	  
}
blackbox stateful_alu flow_prot_write_alu {
	reg: flow_prot;
	update_lo_1_value: ipv4.protocol;
}
action read_prot_1() {
	flow_prot_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action write_prot_1() {
	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action read_prot_2() {
	flow_prot_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action write_prot_2() {
	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_prot_3() {
	flow_prot_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action write_prot_3() {
	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action promote_prot() {
	flow_prot_write_alu.execute_stateful_alu(measurement_meta.min_idx);
}
table read_prot_one_t {
	actions {
		read_prot_1;
	}
	default_action: read_prot_1;
}
table write_prot_one_t {
	actions {
		write_prot_1;
	}
	default_action: write_prot_1;
}
table read_prot_two_t {
	actions {
		read_prot_2;
	}
	default_action: read_prot_2;
}
table write_prot_two_t {
	actions {
		write_prot_2;
	}
	default_action: write_prot_2;
}
table read_prot_three_t {
	actions {
		read_prot_3;
	}
	default_action: read_prot_3;
}
table write_prot_three_t {
	actions {
		write_prot_3;
	}
	default_action: write_prot_3;
}
table promote_prot_t {
	actions {
		promote_prot;
	}
	default_action: promote_prot;
}

// register for ports:
register flow_port_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
register flow_port_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
register flow_port_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_srcport_read_alu {
	reg: flow_port;
	output_value: register_lo;
	output_dst: measurement_meta.srcport;	  
}
blackbox stateful_alu flow_dstport_read_alu {
	reg: flow_port;
	output_value: register_hi;
	output_dst: measurement_meta.dstport;	  
}
blackbox stateful_alu flow_port_write_alu {
	reg: flow_port;
	update_lo_1_value: tcp.srcPort;
	update_hi_1_value: tcp.dstPort;
}
action read_srcport_1() {
	flow_srcport_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action read_dstport_1() {
	flow_dstport_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action write_port_1() {
	flow_port_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action read_srcport_2() {
	flow_srcport_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_dstport_2() {
	flow_dstport_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action write_port_2() {
	flow_port_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_srcport_3() {
	flow_srcport_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action read_dstport_3() {
	flow_dstport_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action write_port_3() {
	flow_port_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action promote_port() {
	flow_port_write_alu.execute_stateful_alu(measurement_meta.min_idx);
}
table read_srcport_one_t {
	actions {
		read_srcport_1;
	}
	default_action: read_srcport_1;
}
table read_dstport_one_t {
	actions {
		read_dstport_1;
	}
	default_action: read_dstport_1;
}
table write_port_one_t {
	actions {
		write_port_1;
	}
	default_action: write_port_1;
}
table read_srcport_two_t {
	actions {
		read_srcport_2;
	}
	default_action: read_srcport_2;
}
table read_dstport_two_t {
	actions {
		read_dstport_2;
	}
	default_action: read_dstport_2;
}
table write_port_two_t {
	actions {
		write_port_2;
	}
	default_action: write_port_2;
}
table read_srcport_three_t {
	actions {
		read_srcport_3;
	}
	default_action: read_srcport_3;
}
table read_dstport_three_t {
	actions {
		read_dstport_3;
	}
	default_action: read_dstport_3;
}
table write_port_three_t {
	actions {
		write_port_3;
	}
	default_action: write_port_3;
}
table promote_port_t {
	actions {
		promote_port;
	}
	default_action: promote_port;
}

// register for packet count:
register pktcnt_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
register pktcnt_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
register pktcnt_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu pktcnt_read_alu {
	reg: pktcnt;
	output_value: register_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu pktcnt_write_alu {
	reg: pktcnt;
	update_lo_1_value: measurement_meta.pktcnt;
}
blackbox stateful_alu pktcnt_set_zero_alu {
	reg: pktcnt;
	update_lo_1_value: 0;
}
blackbox stateful_alu pktcnt_set_one_alu {
	reg: pktcnt;
	update_lo_1_value: 1;
}
blackbox stateful_alu pktcnt_incre_alu {
	reg: pktcnt;
	update_lo_1_value: register_lo + 1;
}
blackbox stateful_alu pktcnt_promotion_alu {
	reg: pktcnt;
	update_lo_1_value: measurement_meta.temp_pktcnt + 1;
}
action read_pktcnt_1() {
	pktcnt_read_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action write_pktcnt_1() {
	pktcnt_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action set_zero_pktcnt_1() {
	pktcnt_set_zero_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action set_one_pktcnt_1() {
	pktcnt_set_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action incre_pktcnt_1() {
	pktcnt_incre_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action read_pktcnt_2() {
	pktcnt_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action write_pktcnt_2() {
	pktcnt_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action set_zero_pktcnt_2() {
	pktcnt_set_zero_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action set_one_pktcnt_2() {
	pktcnt_set_one_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action incre_pktcnt_2() {
	pktcnt_incre_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action read_pktcnt_3() {
	pktcnt_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action write_pktcnt_3() {
	pktcnt_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action set_zero_pktcnt_3() {
	pktcnt_set_zero_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action set_one_pktcnt_3() {
	pktcnt_set_one_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action incre_pktcnt_3() {
	pktcnt_incre_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action promote_pktcnt() {
	pktcnt_promotion_alu.execute_stateful_alu(measurement_meta.min_idx);
}
table read_pktcnt_one_t {
	actions {read_pktcnt_1;}
	default_action: read_pktcnt_1;
}
table write_pktcnt_one_t {
	actions {write_pktcnt_1;}
	default_action: write_pktcnt_1;
}
table set_zero_pktcnt_one_t {
	actions {set_zero_pktcnt_1;}
	default_action: set_zero_pktcnt_1;
}
table set_one_pktcnt_one_t {
	actions {set_one_pktcnt_1;}
	default_action: set_one_pktcnt_1;
}
table incre_pktcnt_one_t {
	actions {incre_pktcnt_1;}
	default_action: incre_pktcnt_1;
}
table read_pktcnt_two_t {
	actions {read_pktcnt_2;}
	default_action: read_pktcnt_2;
}
table write_pktcnt_two_t {
	actions {write_pktcnt_2;}
	default_action: write_pktcnt_2;
}
table set_zero_pktcnt_two_t {
	actions {set_zero_pktcnt_2;}
	default_action: set_zero_pktcnt_2;
}
table set_one_pktcnt_two_t {
	actions {set_one_pktcnt_2;}
	default_action: set_one_pktcnt_2;
}
table incre_pktcnt_two_t {
	actions {incre_pktcnt_2;}
	default_action: incre_pktcnt_2;
}
table read_pktcnt_three_t {
	actions {read_pktcnt_3;}
	default_action: read_pktcnt_3;
}
table write_pktcnt_three_t {
	actions {write_pktcnt_3;}
	default_action: write_pktcnt_3;
}
table set_zero_pktcnt_three_t {
	actions {set_zero_pktcnt_3;}
	default_action: set_zero_pktcnt_3;
}
table set_one_pktcnt_three_t {
	actions {set_one_pktcnt_3;}
	default_action: set_one_pktcnt_3;
}
table incre_pktcnt_three_t {
	actions {incre_pktcnt_3;}
	default_action: incre_pktcnt_3;
}
table promote_pktcnt_t {
	actions {promote_pktcnt;}
	default_action: promote_pktcnt;
}*/

// register for digest
/*register digest {
	width: 8;
	instance_count: ANCILLARY_TABLE_SIZE;
}
blackbox stateful_alu digest_read_alu {
	reg: digest;
	output_value: register_lo;
	output_dst: measurement_meta.digest;
}
blackbox stateful_alu digest_write_alu {
	reg: digest;
	update_lo_1_value: measurement_meta.current_digest;
}
action read_digest() {
	digest_read_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action write_digest() {
	digest_write_alu.execute_stateful_alu(measurement_meta.a_idx);
}
table read_digest_t {
	actions {read_digest;}
	default_action: read_digest;
}
table write_digest_t {
	actions {write_digest;}
	default_action: write_digest;
}

// register for temp_pktcnt
register temp_pktcnt {
	width: 8;
	instance_count: ANCILLARY_TABLE_SIZE;
}
blackbox stateful_alu temp_pktcnt_read_alu {
	reg: temp_pktcnt;
	output_value: register_lo;
	output_dst: measurement_meta.temp_pktcnt;	  
}
blackbox stateful_alu temp_pktcnt_write_alu {
	reg: temp_pktcnt;
	update_lo_1_value: measurement_meta.temp_pktcnt;
}
blackbox stateful_alu temp_pktcnt_set_zero_alu {
	reg: temp_pktcnt;
	update_lo_1_value: 0;
}
blackbox stateful_alu temp_pktcnt_set_one_alu {
	reg: temp_pktcnt;
	update_lo_1_value: 1;
}
blackbox stateful_alu temp_pktcnt_incre_alu {
	reg: temp_pktcnt;
	update_lo_1_value: register_lo + 1;
}

action read_temp_pktcnt() {
	temp_pktcnt_read_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action write_temp_pktcnt() {
	temp_pktcnt_write_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action set_zero_temp_pktcnt() {
	temp_pktcnt_set_zero_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action set_one_temp_pktcnt() {
	temp_pktcnt_set_one_alu.execute_stateful_alu(measurement_meta.a_idx);
//	modify_field(measurement_meta.temp, measurement_meta.a_idx);
}
action incre_temp_pktcnt() {
	temp_pktcnt_incre_alu.execute_stateful_alu(measurement_meta.a_idx);
}

table read_temp_pktcnt_t {
	actions {read_temp_pktcnt;}
	default_action: read_temp_pktcnt;
}
table write_temp_pktcnt_t {
	actions {write_temp_pktcnt;}
	default_action: write_temp_pktcnt;
}
table set_zero_temp_pktcnt_t {
	actions {set_zero_temp_pktcnt;}
	default_action: set_zero_temp_pktcnt;
}
table set_one_temp_pktcnt_t {
	actions {set_one_temp_pktcnt;}
	default_action: set_one_temp_pktcnt;
}
table incre_temp_pktcnt_t {
	actions {incre_temp_pktcnt;}
	default_action: incre_temp_pktcnt;
}*/

register flag {
	width: 32;
	instance_count: 1;
}
blackbox stateful_alu set_flag_alu_1 {
	reg: flag;
	condition_lo: measurement_meta.pktcnt < measurement_meta.min_value;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: 1;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: 0;
	output_value: alu_lo;
	output_dst: measurement_meta.flag;
}
blackbox stateful_alu set_flag_alu_2 {
	reg: flag;
	condition_lo: measurement_meta.temp_pktcnt >= measurement_meta.min_value;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: 1;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: 0;
	output_value: alu_lo;
	output_dst: measurement_meta.flag;
}
blackbox stateful_alu compare_digest {
	reg: flag;
	condition_lo: measurement_meta.digest == measurement_meta.current_digest;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: 1;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: 0;
	output_value: alu_lo;
	output_dst: measurement_meta.flag_same_digest;
}
//action update_main_table_1() {
//	flow_srcip_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_dstip_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_srcport_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	flow_dstport_write_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	packet_count_incre_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	modify_field(measurement_meta.status, 1);
//}

//action read_main_table_2() {
//	flow_srcip_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_dstip_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_prot_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_srcport_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_dstport_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	packet_count_read_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//}
//action update_main_table_2() {
//	flow_srcip_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_dstip_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_srcport_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	flow_dstport_write_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	packet_count_incre_alu.execute_stateful_alu(measurement_meta.m_idx_2);
//	modify_field(measurement_meta.status, 1);
//}

//action read_main_table_3() {
//	flow_srcip_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_dstip_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_prot_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_srcport_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_dstport_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	packet_count_read_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//}
//action update_main_table_3() {
//	flow_srcip_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_dstip_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_prot_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_srcport_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	flow_dstport_write_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	packet_count_incre_alu.execute_stateful_alu(measurement_meta.m_idx_3);
//	modify_field(measurement_meta.status, 1);
//}

//action read_ancillary_table() {
//	digest_read_alu.execute_stateful_alu(measurement_meta.a_idx);
//	temp_packet_count_read_alu.execute_stateful_alu(measurement_meta.a_idx);
//}
//action init_ancillary_table() {
//	digest_write_alu.execute_stateful_alu(measurement_meta.a_idx);
//	temp_packet_count_set_one_alu.execute_stateful_alu(measurement_meta.a_idx);
//}
//action update_ancillary_table() {
//	digest_write_alu.execute_stateful_alu(measurement_meta.a_idx);
//	temp_packet_count_incre_alu.execute_stateful_alu(measurement_meta.a_idx);
//	modify_field_conditionally(measurement_meta.flag, 
//		measurement_meta.min_value <= measurement_meta.temp_pktcnt, 1);
//	set_flag_alu_2.execute_stateful_alu(0);
//}

action _nop() {
}

action set_flag_1() {
	set_flag_alu_1.execute_stateful_alu(0);
}
table set_flag_one_t {
	actions {set_flag_1;}
	default_action: set_flag_1;
}

action set_flag_2() {
	set_flag_alu_2.execute_stateful_alu(0);
}
table set_flag_two_t {
	actions {set_flag_2;}
	default_action: set_flag_2;
}

action set_status() {
	modify_field(measurement_meta.status, 1);
}

table set_status_t {
	actions {set_status;}
	default_action: set_status;
}

action update_min_1() {
	record_flow_pktcnt_one_alu.execute_stateful_alu();
	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_1);
}

action update_min_2() {
	modify_field(measurement_meta.min_value, measurement_meta.pktcnt);
	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_2);
}

action update_min_3() {
	modify_field(measurement_meta.min_value, measurement_meta.pktcnt);
	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_3);
}

action pkt_xor_temp() {
	bit_xor(measurement_meta.srcip, measurement_meta.srcip, ipv4.srcAddr);	
	bit_xor(measurement_meta.dstip, measurement_meta.dstip, ipv4.dstAddr);
	bit_xor(measurement_meta.srcport, measurement_meta.srcport, tcp.srcPort);
	bit_xor(measurement_meta.dstport, measurement_meta.dstport, tcp.dstPort);
	bit_xor(measurement_meta.prot, measurement_meta.prot, ipv4.protocol);
}

action main_idx_one_calc () {
	modify_field_with_hash_based_offset(measurement_meta.m_idx_1, 0, 
		main_hash_1, SUB_TABLE_A_SIZE);
}
action main_idx_two_calc () {
	modify_field_with_hash_based_offset(measurement_meta.m_idx_2, 
		SUB_TABLE_A_SIZE, main_hash_2, SUB_TABLE_B_SIZE);
}
action main_idx_three_calc () {
	modify_field_with_hash_based_offset(measurement_meta.m_idx_3, 
		SUB_TABLE_A_SIZE+SUB_TABLE_B_SIZE, main_hash_3, SUB_TABLE_C_SIZE);
}
action ancillary_idx_calc () {
	modify_field_with_hash_based_offset(measurement_meta.a_idx,0, 
		ancillary_hash, ANCILLARY_TABLE_SIZE);
}
action digest_calc () {
	modify_field_with_hash_based_offset(measurement_meta.current_digest, 0,
		digest_hash, 256);
}

table main_idx_one_calc_t {
	actions {main_idx_one_calc;}
	default_action: main_idx_one_calc;
}
table main_idx_two_calc_t {
	actions {main_idx_two_calc;}
	default_action: main_idx_two_calc;
}
table main_idx_three_calc_t {
	actions {main_idx_three_calc;}
	default_action: main_idx_three_calc;
}
table ancillary_idx_calc_t {
	actions {ancillary_idx_calc;}
	default_action: ancillary_idx_calc;
}
table digest_calc_t {
	actions {digest_calc;}
	default_action: digest_calc;
}

//action main_idx_calc_a () {
//	modify_field_with_hash_based_offset(measurement_meta.main_table_idx, 0, 
//		main_hash_1, SUB_TABLE_A_SIZE);
//////////
//	register_read(temp_meta.n_pkts, temp_register, 0);
//	register_read(temp_meta.n_hashes, temp_register, 1);
//	register_read(temp_meta.n_mem_access, temp_register, 2);
//	add_to_field(temp_meta.n_pkts, 1);
//	register_write(temp_register, 0, temp_meta.n_pkts);
//	add_to_field(temp_meta.n_hashes, 1);
//	register_write(temp_register, 1, temp_meta.n_hashes);
//////////
//}

//action main_idx_calc_b () {
//	modify_field_with_hash_based_offset(measurement_meta.main_table_idx, 
//		SUB_TABLE_A_SIZE, main_hash_2, SUB_TABLE_B_SIZE);
//////////
//	add_to_field(temp_meta.n_hashes, 1);
//	register_write(temp_register, 1, temp_meta.n_hashes);
//////////
//}

//action main_idx_calc_c () {
//	modify_field_with_hash_based_offset(measurement_meta.main_table_idx, 
//		SUB_TABLE_A_SIZE+SUB_TABLE_B_SIZE, main_hash_3, SUB_TABLE_C_SIZE);
//////////
//	add_to_field(temp_meta.n_hashes, 1);
//	register_write(temp_register, 1, temp_meta.n_hashes);
//////////
//}

//action ancillary_idx_calc () {
//	modify_field_with_hash_based_offset(measurement_meta.ancillary_table_idx,0, 
//		ancillary_hash, ANCILLARY_TABLE_SIZE);
//////////
//	add_to_field(temp_meta.n_hashes, 1);
//	register_write(temp_register, 1, temp_meta.n_hashes);
//////////
//}

//action read_main_table () {
//	register_read(measurement_meta.srcip, flow_srcip, 
//			measurement_meta.main_table_idx);
//	register_read(measurement_meta.dstip, flow_dstip, 
//			measurement_meta.main_table_idx);
//	register_read(measurement_meta.srcport, flow_srcport, 
//			measurement_meta.main_table_idx);
//	register_read(measurement_meta.dstport, flow_dstport, 
//			measurement_meta.main_table_idx);
//	register_read(measurement_meta.prot, flow_prot, 
//			measurement_meta.main_table_idx);
//	register_read(measurement_meta.pktcnt, packet_count, 
//		measurement_meta.main_table_idx);
//////////
//	add_to_field(temp_meta.n_mem_access, 6);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action read_ancillary_table() {
//	register_read(measurement_meta.temp_pktcnt, temp_packet_count,
//			measurement_meta.ancillary_table_idx);
//	register_read(measurement_meta.digest, digest, 
//			measurement_meta.ancillary_table_idx);
//////////
//	add_to_field(temp_meta.n_mem_access, 2);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action update_main_data() {
//	register_write(flow_srcip, measurement_meta.main_table_idx, 
//			ipv4.srcAddr);
//	register_write(flow_dstip, measurement_meta.main_table_idx, 
//			ipv4.dstAddr);
//	register_write(flow_srcport, measurement_meta.main_table_idx, 
//			tcp.srcPort);
//	register_write(flow_dstport, measurement_meta.main_table_idx, 
//			tcp.dstPort);
//	register_write(flow_prot, measurement_meta.main_table_idx, 
//			ipv4.protocol);
//	register_write(packet_count, measurement_meta.main_table_idx, 1);
//	modify_field(measurement_meta.main_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 6);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action update_packet_count () {
//	register_write(packet_count, measurement_meta.main_table_idx, 
//			measurement_meta.pktcnt + 1);
//	modify_field(measurement_meta.main_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 1);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action promote() {
//	register_write(flow_srcip, measurement_meta.min_idx, ipv4.srcAddr);
//	register_write(flow_dstip, measurement_meta.min_idx, ipv4.dstAddr);
//	register_write(flow_srcport, measurement_meta.min_idx, tcp.srcPort);
//	register_write(flow_dstport, measurement_meta.min_idx, tcp.dstPort);
//	register_write(flow_prot, measurement_meta.min_idx, ipv4.protocol);
//	register_write(packet_count, measurement_meta.min_idx, 
//			measurement_meta.temp_pktcnt + 1);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//	flow_srcip_write_alu.execute_stateful_alu(measurement_meta.min_idx);	
//	flow_dstip_write_alu.execute_stateful_alu(measurement_meta.min_idx);	
//	flow_prot_write_alu.execute_stateful_alu(measurement_meta.min_idx);	
//	flow_srcport_write_alu.execute_stateful_alu(measurement_meta.min_idx);	
//	flow_dstport_write_alu.execute_stateful_alu(measurement_meta.min_idx);	
//	packet_count_promotion.execute_stateful_alu(measurement_meta.min_idx);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 6);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action update_ancillary_empty () {
//	register_write(temp_packet_count, measurement_meta.a_idx,1);
//	register_write(digest, measurement_meta.a_idx,
//			measurement_meta.current_digest);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//	temp_packet_count_set_one_alu.execute_stateful_alu(measurement_meta.a_idx);
//	digest_write_alu.execute_stateful_alu(measurement_meta.a_idx);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 2);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action update_ancillary_collision () {
//	register_write(temp_packet_count, measurement_meta.a_idx,1);
//	register_write(digest, measurement_meta.a_idx,
//			measurement_meta.current_digest);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//	temp_packet_count_set_one_alu.execute_stateful_alu(measurement_meta.a_idx);
//	digest_write_alu.execute_stateful_alu(measurement_meta.a_idx);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 2);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

//action update_temp_packet_count () {
//	register_write(temp_packet_count, measurement_meta.ancillary_table_idx,
//			measurement_meta.temp_pktcnt + 1);
//	temp_packet_count_incre_alu.execute_stateful_alu(measurement_meta.a_idx);
//	modify_field(measurement_meta.ancillary_status, COMPLETE_UPDATE);
//////////
//	add_to_field(temp_meta.n_mem_access, 1);
//	register_write(temp_register, 2, temp_meta.n_mem_access);
//////////
//}

action digest_subtraction () {
	subtract_from_field(measurement_meta.digest, 
		measurement_meta.current_digest);
//	compare_digest.execute_stateful_alu(0);
}
//tables:
//table idx_and_digest_calc_t {
//	actions {
//		idx_and_digest_calc;
//	}
//	default_action: idx_and_digest_calc;
//}

//table main_idx_calc_b_t {
//	actions {
//		main_idx_calc_b;
//	}
//}
//table main_idx_calc_c_t {
//	actions {
//		main_idx_calc_c;
//	}
//}
//table ancillary_idx_calc_t {
//	actions {
//		ancillary_idx_calc;
//	}
//}

//table read_main_data_a_t {
//	actions {
//		read_main_table_1;
//	}
//}

//table read_main_data_b_t {
//	actions {
//		read_main_table_2;
//	}
//}

//table read_main_data_c_t {
//	actions {
//		read_main_table_3;
//	}
//}

table compare_for_empty_one_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		pkt_xor_temp;
	}
	default_action: pkt_xor_temp;
}

table compare_for_matching_one_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		update_min_1;
	}
	default_action: update_min_1;
}

table compare_for_empty_two_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		pkt_xor_temp;
	}
	default_action: pkt_xor_temp;
}

table compare_for_matching_two_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		set_flag_1;
	}
	default_action: set_flag_1;
}

table compare_for_empty_three_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		pkt_xor_temp;
	}
	default_action: pkt_xor_temp;
}

table compare_for_matching_three_t {
	reads {
		measurement_meta.srcip: exact;
		measurement_meta.dstip: exact;
		measurement_meta.srcport: exact;
		measurement_meta.dstport: exact;
		measurement_meta.prot: exact;
	}
	actions {
		set_status;
		set_flag_1;
	}
	default_action: set_flag_1;
}

//table read_ancillary_data_t {
//	actions {
//		read_ancillary_table;
//	}
//}

table ancillary_compare_for_empty_t {
	reads {
		measurement_meta.digest: exact;
	}
	actions {
//		set_one_temp_pktcnt;
		_nop;
		digest_subtraction;
	}
	default_action: digest_subtraction;
	size: 256;
}

table ancillary_compare_for_matching_t {
	reads {
		measurement_meta.digest: exact;
//		measurement_meta.flag_same_digest: exact;
	}
	actions {
//		set_one_temp_pktcnt;
		_nop;
		set_flag_2;
	}
	default_action: _nop;
	size: 256;		
}

//table update_ancillary_data_t {
//	reads {
//		measurement_meta.ancillary_status: exact;
//		measurement_meta.digest: exact;
//	}
//	actions {
//		update_ancillary_collision;
//		update_temp_packet_count;
//	}
//}

table update_min_two_t {
	actions {
		update_min_2;
	}
	default_action: update_min_2;
}

table update_min_three_t {
	actions {
		update_min_3;
	}
default_action: update_min_3;
}

//table promotion_t {
//	actions {
//		promote;
//	}
//	default_action: promote;
//}

// debug
header_type temp_meta_t {
	fields {
		n_pkts: 32;
		n_hashes: 32;
		n_mem_access: 32;
	}
}
metadata temp_meta_t temp_meta;

register temp_register {
	width: 32;
	instance_count: 3;	
}

action m_action() {
}

table m_table {
	actions {
		m_action;
	}
}

control idx_and_digest_calc {
	apply(main_idx_one_calc_t);
	apply(main_idx_two_calc_t);
	apply(main_idx_three_calc_t);
	apply(ancillary_idx_calc_t);
	apply(digest_calc_t);
}

control read_main_data_1 {
	apply(process_flow_srcip_one_t);
	apply(process_flow_dstip_one_t);
	apply(process_flow_proto_one_t);
	apply(process_flow_srcport_one_t);
	apply(process_flow_dstport_one_t);
}

control read_main_data_2 {
	apply(process_flow_srcip_two_t);
	apply(process_flow_dstip_two_t);
	apply(process_flow_proto_two_t);
	apply(process_flow_srcport_two_t);
	apply(process_flow_dstport_two_t);
}

control read_main_data_3 {
	apply(process_flow_srcip_three_t);
	apply(process_flow_dstip_three_t);
	apply(process_flow_proto_three_t);
	apply(process_flow_srcport_three_t);
	apply(process_flow_dstport_three_t);
}

control read_ancillary_data {
	apply(read_digest_t);
	apply(read_temp_pktcnt_t);
}
