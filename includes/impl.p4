// pre-compile commands:

#include "table_size.p4"

#define MAIN_TABLE_IDX_WIDTH 10
#define ANCILLARY_TABLE_IDX_WIDTH 12
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
		pktcnt: 32;
		srcip_flag: 4;
		dstip_flag: 4;
		proto_flag: 4;
		srcport_flag: 4;
		dstport_flag: 4;
		digest_flag: 4;
		temp_pktcnt: 8;
		current_digest: 8;
		status: 1;	// whether the packet has been recorded
		flag: 32;
		promotion: 1;
		min_value: 32;
		stage: 4;
		flow_table_no: 4;
	}
}

metadata measurement_metadata_t measurement_meta;

action set_promotion_flag() {
	modify_field(measurement_meta.promotion, 1);
//	modify_field(measurement_meta.status, 1);
}
table set_promotion_flag_t {
	reads {
		measurement_meta.flag mask 0x80000000: exact;
	}
	actions {set_promotion_flag;}
	default_action: set_promotion_flag;
	size: 2;
}

// register for stage I:
register test_reg {
	width: 32;
	instance_count: 100;
}
blackbox stateful_alu test_reg_alu {
	reg: test_reg;
	update_lo_1_value: register_lo + 1;
}

register flow_srcip_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_srcip_one_alu {
	reg: flow_srcip_1;
	condition_lo: 0 == register_lo;
	condition_hi: ipv4.srcip == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.srcip;
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcip_flag;
}

action process_flow_srcip_1() {
	flow_srcip_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	flow_srcip_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_srcip_one_t {
	actions {process_flow_srcip_1;}
	default_action: process_flow_srcip_1;
}
blackbox stateful_alu write_flow_srcip_alu_1 {
	reg: flow_srcip_1;
	update_lo_1_value: ipv4.srcip;
}
action write_flow_srcip_1() {
	write_flow_srcip_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table write_flow_srcip_t_1 {
	actions {write_flow_srcip_1;}
}
table process_flow_srcip_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcip_1;
		write_flow_srcip_1;	
	}
}

action m_action() {
	test_reg_alu.execute_stateful_alu(0);
}

table m_table {
	actions {m_action;}
	default_action: m_action;
}

register flow_dstip_1 {
	width: 32;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_dstip_one_alu {
	reg: flow_dstip_1;
	condition_lo: 0 == register_lo;
	condition_hi: ipv4.dstip == register_lo; 
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.dstip;
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_1() {
	flow_dstip_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	flow_dstip_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_dstip_one_t {
	actions {process_flow_dstip_1;}
	default_action: process_flow_dstip_1;
}
blackbox stateful_alu write_flow_dstip_alu_1 {
	reg: flow_dstip_1;
	update_lo_1_value: ipv4.dstip;
}
action write_flow_dstip_1() {
	write_flow_dstip_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table write_flow_dstip_t_1 {
	actions {write_flow_dstip_1;}
}
table process_flow_dstip_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstip_1;
		write_flow_dstip_1;	
	}
}

register flow_proto_1 {
	width: 8;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_proto_one_alu {
	reg: flow_proto_1;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.proto;
	condition_hi: ipv4.proto == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_1() {
	flow_proto_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	flow_proto_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_proto_one_t {
	actions {process_flow_proto_1;}
	default_action: process_flow_proto_1;
}
blackbox stateful_alu write_flow_proto_alu_1 {
	reg: flow_proto_1;
	update_lo_1_value: ipv4.proto;
}
action write_flow_proto_1() {
	write_flow_proto_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table write_flow_proto_t_1 {
	actions {write_flow_proto_1;}
}
table process_flow_proto_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_proto_1;
		write_flow_proto_1;	
	}
}

register flow_srcport_1 {
	width: 16;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_srcport_one_alu {
	reg: flow_srcport_1;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.srcport;
	condition_hi: tcp.srcport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_1() {
	flow_srcport_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	flow_srcport_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_srcport_one_t {
	actions {process_flow_srcport_1;}
	default_action: process_flow_srcport_1;
}
blackbox stateful_alu write_flow_srcport_alu_1 {
	reg: flow_srcport_1;
	update_lo_1_value: tcp.srcport;
}
action write_flow_srcport_1() {
	write_flow_srcport_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table write_flow_srcport_t_1 {
	actions {write_flow_srcport_1;}
}
table process_flow_srcport_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcport_1;
		write_flow_srcport_1;	
	}
}

register flow_dstport_1 {
	width: 16;
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu flow_dstport_one_alu {
	reg: flow_dstport_1;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.dstport;
	condition_hi: tcp.dstport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_1() {
	flow_dstport_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	flow_dstport_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
table process_flow_dstport_one_t {
	actions {process_flow_dstport_1;}
	default_action: process_flow_dstport_1;
}
blackbox stateful_alu write_flow_dstport_alu_1 {
	reg: flow_dstport_1;
	update_lo_1_value: tcp.dstport;
}
action write_flow_dstport_1() {
	write_flow_dstport_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table write_flow_dstport_t_1 {
	actions {write_flow_dstport_1;}
}
table process_flow_dstport_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstport_1;
		write_flow_dstport_1;	
	}
}

register flow_pktcnt_1 {
	width: 32;	
	instance_count: SUB_TABLE_A_SIZE;
}
blackbox stateful_alu record_flow_pktcnt_one_alu {
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
	set_one_flow_pktcnt_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	set_one_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action incre_flow_pktcnt_1() {
	incre_flow_pktcnt_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	incre_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
}
action find_matching_entry_1() {
//	incre_flow_pktcnt_1();
	incre_flow_pktcnt_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	incre_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
	modify_field(measurement_meta.status, 1);
}
table compare_t_1 {
	reads {
		measurement_meta.promotion: exact;
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.proto_flag: exact;
	}
	actions {
		find_matching_entry_1;
		update_min_1;
		promote_flow_pktcnt_1;
	}
//	default_action: update_min_1;
	size: 4;
}
blackbox stateful_alu promote_flow_pktcnt_alu_1 {
	reg: flow_pktcnt_1;
	update_lo_1_value: measurement_meta.temp_pktcnt + 1;
}
action promote_flow_pktcnt_1() {
	promote_flow_pktcnt_alu_1.execute_stateful_alu_from_hash(main_hash_1);
}
table promote_flow_pktcnt_t_1 {
	actions {promote_flow_pktcnt_1;}
}

// register for stage II:
register flow_srcip_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_srcip_two_alu {
	reg: flow_srcip_2;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.srcip;
	condition_hi: ipv4.srcip == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcip_flag;
}
action process_flow_srcip_2() {
	flow_srcip_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	flow_srcip_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_srcip_two_t {
	actions {process_flow_srcip_2;}
	default_action: process_flow_srcip_2;
}
blackbox stateful_alu write_flow_srcip_alu_2 {
	reg: flow_srcip_2;
	update_lo_1_value: ipv4.srcip;
}
action write_flow_srcip_2() {
	write_flow_srcip_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table write_flow_srcip_t_2 {
	actions {write_flow_srcip_2;}
}
table process_flow_srcip_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcip_2;
		write_flow_srcip_2;	
	}
}

register flow_dstip_2 {
	width: 32;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_dstip_two_alu {
	reg: flow_dstip_2;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.dstip;
	condition_hi: ipv4.dstip == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_2() {
	flow_dstip_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	flow_dstip_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_dstip_two_t {
	actions {process_flow_dstip_2;}
	default_action: process_flow_dstip_2;
}
blackbox stateful_alu write_flow_dstip_alu_2 {
	reg: flow_dstip_2;
	update_lo_1_value: ipv4.dstip;
}
action write_flow_dstip_2() {
	write_flow_dstip_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table write_flow_dstip_t_2 {
	actions {write_flow_dstip_2;}
}
table process_flow_dstip_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstip_2;
		write_flow_dstip_2;	
	}
}


register flow_proto_2 {
	width: 8;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_proto_two_alu {
	reg: flow_proto_2;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.proto;
	condition_hi: ipv4.proto == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_2() {
	flow_proto_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	flow_proto_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_proto_two_t {
	actions {process_flow_proto_2;}
	default_action: process_flow_proto_2;
}
blackbox stateful_alu write_flow_proto_alu_2 {
	reg: flow_proto_2;
	update_lo_1_value: ipv4.proto;
}
action write_flow_proto_2() {
	write_flow_proto_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table write_flow_proto_t_2 {
	actions {write_flow_proto_2;}
}
table process_flow_proto_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_proto_2;
		write_flow_proto_2;	
	}
}

register flow_srcport_2 {
	width: 16;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_srcport_two_alu {
	reg: flow_srcport_2;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.srcport;
	condition_hi: tcp.srcport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_2() {
	flow_srcport_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	flow_srcport_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_srcport_two_t {
	actions {process_flow_srcport_2;}
	default_action: process_flow_srcport_2;
}
blackbox stateful_alu write_flow_srcport_alu_2 {
	reg: flow_srcport_2;
	update_lo_1_value: tcp.srcport;
}
action write_flow_srcport_2() {
	write_flow_srcport_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table write_flow_srcport_t_2 {
	actions {write_flow_srcport_2;}
}
table process_flow_srcport_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcport_2;
		write_flow_srcport_2;	
	}
}

register flow_dstport_2 {
	width: 16;
	instance_count: SUB_TABLE_B_SIZE;
}
blackbox stateful_alu flow_dstport_two_alu {
	reg: flow_dstport_2;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.dstport;
	condition_hi: tcp.dstport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_2() {
	flow_dstport_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	flow_dstport_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table process_flow_dstport_two_t {
	actions {process_flow_dstport_2;}
	default_action: process_flow_dstport_2;
}
blackbox stateful_alu write_flow_dstport_alu_2 {
	reg: flow_dstport_2;
	update_lo_1_value: tcp.dstport;
}
action write_flow_dstport_2() {
	write_flow_dstport_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table write_flow_dstport_t_2 {
	actions {write_flow_dstport_2;}
}
table process_flow_dstport_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstport_2;
		write_flow_dstport_2;	
	}
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
	reg: flow_pktcnt_2;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu read_flow_pktcnt_two_alu {
	reg: flow_pktcnt_2;
	update_lo_1_value: register_lo;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
action set_one_flow_pktcnt_2() {
	set_one_flow_pktcnt_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	set_one_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action incre_flow_pktcnt_2() {
	incre_flow_pktcnt_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	incre_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
action find_matching_entry_2() {
	incre_flow_pktcnt_2();
	modify_field(measurement_meta.status, 1);
}
action read_pktcnt_2() {
	read_flow_pktcnt_two_alu.execute_stateful_alu_from_hash(main_hash_2);
//	read_flow_pktcnt_two_alu.execute_stateful_alu(measurement_meta.m_idx_2);
}
table compare_t_2 {
	reads {
		measurement_meta.promotion: exact;
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.proto_flag: exact;
	}
	actions {
		find_matching_entry_2;
		read_pktcnt_2;
		promote_flow_pktcnt_2;
	}
//	default_action: read_pktcnt_2;
	size: 4;
}
blackbox stateful_alu promote_flow_pktcnt_alu_2 {
	reg: flow_pktcnt_2;
	update_lo_1_value: measurement_meta.temp_pktcnt + 1;
}
action promote_flow_pktcnt_2() {
	promote_flow_pktcnt_alu_2.execute_stateful_alu_from_hash(main_hash_2);
}
table promote_flow_pktcnt_t_2 {
	actions {promote_flow_pktcnt_2;}
}

// register for stage III:
register flow_srcip_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_srcip_three_alu {
	reg: flow_srcip_3;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.srcip;
	condition_hi: ipv4.srcip == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcip_flag;
}
action process_flow_srcip_3() {
	flow_srcip_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	flow_srcip_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_srcip_three_t {
	actions {process_flow_srcip_3;}
	default_action: process_flow_srcip_3;
}
blackbox stateful_alu write_flow_srcip_alu_3 {
	reg: flow_srcip_3;
	update_lo_1_value: ipv4.srcip;
}
action write_flow_srcip_3() {
	write_flow_srcip_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table write_flow_srcip_t_3 {
	actions {write_flow_srcip_3;}
}
table process_flow_srcip_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcip_3;
		write_flow_srcip_3;	
	}
}

register flow_dstip_3 {
	width: 32;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_dstip_three_alu {
	reg: flow_dstip_3;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.dstip;
	condition_hi: ipv4.dstip == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.dstip_flag;
}
action process_flow_dstip_3() {
	flow_dstip_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	flow_dstip_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_dstip_three_t {
	actions {process_flow_dstip_3;}
	default_action: process_flow_dstip_3;
}
blackbox stateful_alu write_flow_dstip_alu_3 {
	reg: flow_dstip_3;
	update_lo_1_value: ipv4.dstip;
}
action write_flow_dstip_3() {
	write_flow_dstip_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table write_flow_dstip_t_3 {
	actions {write_flow_dstip_3;}
}
table process_flow_dstip_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstip_3;
		write_flow_dstip_3;	
	}
}

register flow_proto_3 {
	width: 8;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_proto_three_alu {
	reg: flow_proto_3;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: ipv4.proto;
	condition_hi: ipv4.proto == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.proto_flag;
}
action process_flow_proto_3() {
	flow_proto_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	flow_proto_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_proto_three_t {
	actions {process_flow_proto_3;}
	default_action: process_flow_proto_3;
}
blackbox stateful_alu write_flow_proto_alu_3 {
	reg: flow_proto_3;
	update_lo_1_value: ipv4.proto;
}
action write_flow_proto_3() {
	write_flow_proto_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table write_flow_proto_t_3 {
	actions {write_flow_proto_3;}
}
table process_flow_proto_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_proto_3;
		write_flow_proto_3;	
	}
}

register flow_srcport_3 {
	width: 16;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_srcport_three_alu {
	reg: flow_srcport_3;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.srcport;
	condition_hi: tcp.srcport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_srcport_3() {
	flow_srcport_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	flow_srcport_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_srcport_three_t {
	actions {process_flow_srcport_3;}
	default_action: process_flow_srcport_3;
}
blackbox stateful_alu write_flow_srcport_alu_3 {
	reg: flow_srcport_3;
	update_lo_1_value: tcp.srcport;
}
action write_flow_srcport_3() {
	write_flow_srcport_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table write_flow_srcport_t_3 {
	actions {write_flow_srcport_3;}
}
table process_flow_srcport_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_srcport_3;
		write_flow_srcport_3;	
	}
}

register flow_dstport_3 {
	width: 16;
	instance_count: SUB_TABLE_C_SIZE;
}
blackbox stateful_alu flow_dstport_three_alu {
	reg: flow_dstport_3;
	condition_lo: 0 == register_lo;
	update_lo_1_predicate: condition_lo;
	update_lo_1_value: tcp.dstport;
	condition_hi: tcp.dstport == register_lo; 
	update_lo_2_predicate: condition_hi; 
	update_lo_2_value: register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.srcport_flag;
}
action process_flow_dstport_3() {
	flow_dstport_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	flow_dstport_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table process_flow_dstport_three_t {
	actions {process_flow_dstport_3;}
	default_action: process_flow_dstport_3;
}
blackbox stateful_alu write_flow_dstport_alu_3 {
	reg: flow_dstport_3;
	update_lo_1_value: tcp.dstport;
}
action write_flow_dstport_3() {
	write_flow_dstport_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table write_flow_dstport_t_3 {
	actions {write_flow_dstport_3;}
}
table process_flow_dstport_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {
		process_flow_dstport_3;
		write_flow_dstport_3;
	}
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
	reg: flow_pktcnt_3;
	update_lo_1_value: register_lo + 1;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
blackbox stateful_alu read_flow_pktcnt_three_alu {
	reg: flow_pktcnt_3;
	update_lo_1_value: register_lo;
	output_value: alu_lo;
	output_dst: measurement_meta.pktcnt;
}
action set_one_flow_pktcnt_3() {
	set_one_flow_pktcnt_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	set_one_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action incre_flow_pktcnt_3() {
	incre_flow_pktcnt_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	incre_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
action find_matching_entry_3() {
	incre_flow_pktcnt_3();
	modify_field(measurement_meta.status, 1);
}
action read_pktcnt_3() {
	read_flow_pktcnt_three_alu.execute_stateful_alu_from_hash(main_hash_3);
//	read_flow_pktcnt_three_alu.execute_stateful_alu(measurement_meta.m_idx_3);
}
table compare_t_3 {
	reads {
		measurement_meta.promotion: exact;
		measurement_meta.srcip_flag: exact;
		measurement_meta.dstip_flag: exact;
		measurement_meta.srcport_flag: exact;
		measurement_meta.dstport_flag: exact;
		measurement_meta.proto_flag: exact;
	}
	actions {
		find_matching_entry_3;
		read_pktcnt_3;
		promote_flow_pktcnt_3;
	}
//	default_action: read_pktcnt_3;
	size: 4;
}
blackbox stateful_alu promote_flow_pktcnt_alu_3 {
	reg: flow_pktcnt_3;
	update_lo_1_value: measurement_meta.temp_pktcnt + 1;
}
action promote_flow_pktcnt_3() {
	promote_flow_pktcnt_alu_3.execute_stateful_alu_from_hash(main_hash_3);
}
table promote_flow_pktcnt_t_3 {
	actions {promote_flow_pktcnt_3;}
}

// register for stage IV:
register digest {
	width: 8;
	instance_count: ANCILLARY_TABLE_SIZE;
}
blackbox stateful_alu process_digest_alu {
	reg: digest;
	update_lo_1_value: measurement_meta.current_digest;
	condition_lo: 0 == register_lo;
	condition_hi: measurement_meta.current_digest == register_lo;
	output_predicate: condition_lo or condition_hi;
	output_value: predicate;
	output_dst: measurement_meta.digest_flag;
}
action process_digest() {
	process_digest_alu.execute_stateful_alu_from_hash(ancillary_hash);
//	process_digest_alu.execute_stateful_alu(measurement_meta.a_idx);
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
	incre_temp_pktcnt_alu.execute_stateful_alu_from_hash(ancillary_hash);
//	incre_temp_pktcnt_alu.execute_stateful_alu(measurement_meta.a_idx);
}
action set_one_temp_pktcnt() {
	set_one_temp_pktcnt_alu.execute_stateful_alu_from_hash(ancillary_hash);
//	set_one_temp_pktcnt_alu.execute_stateful_alu(measurement_meta.a_idx);
}
table ancillary_compare_t {
	reads {measurement_meta.digest_flag: exact;}
	actions {
		incre_temp_pktcnt;
		set_one_temp_pktcnt;
	}
//	default_action: set_one_temp_pktcnt;
	size: 2;
}

action min_value_subtract_pktcnt() {
	subtract(measurement_meta.flag, measurement_meta.min_value, measurement_meta.pktcnt);
}
//register flag_1 {
//	width: 32;
//	instance_count: 1;
//}
//blackbox stateful_alu set_flag_alu_1 {
//	reg: flag_1;
//	condition_lo: measurement_meta.pktcnt < measurement_meta.min_value;
//	update_lo_1_predicate: condition_lo;
//	update_lo_1_value: 1;
//	update_lo_2_predicate: not condition_lo;
//	update_lo_2_value: 0;
//	output_value: alu_lo;
//	output_dst: measurement_meta.flag;
//}
//action set_flag_1() {
//	set_flag_alu_1.execute_stateful_alu(0);
//}
table set_flag_one_t {
	actions {min_value_subtract_pktcnt;}
	default_action: min_value_subtract_pktcnt;
}

//register flag_2 {
//	width: 32;
//	instance_count: 1;
//}
//blackbox stateful_alu set_flag_alu_2 {
//	reg: flag_2;
//	condition_lo: measurement_meta.pktcnt < measurement_meta.min_value;
//	update_lo_1_predicate: condition_lo;
//	update_lo_1_value: 1;
//	update_lo_2_predicate: not condition_lo;
//	update_lo_2_value: 0;
//	output_value: alu_lo;
//	output_dst: measurement_meta.flag;
//}
//action set_flag_2() {
//	set_flag_alu_2.execute_stateful_alu(0);
//}
table set_flag_two_t {
	actions {min_value_subtract_pktcnt;}
	default_action: min_value_subtract_pktcnt;
}

//register flag_3 {
//	width: 32;
//	instance_count: 1;
//}
action temp_pktcnt_subtract_min_value() {
	subtract(measurement_meta.flag, measurement_meta.temp_pktcnt,
		measurement_meta.min_value);
}
//blackbox stateful_alu set_flag_alu_3 {
//	reg: flag_3;
//	condition_lo: measurement_meta.temp_pktcnt >= measurement_meta.min_value;
//	update_lo_1_predicate: condition_lo;
//	update_lo_1_value: 1;
//	update_lo_2_predicate: not condition_lo;
//	update_lo_2_value: 0;
//	output_value: alu_lo;
//	output_dst: measurement_meta.flag;
//}
//action set_flag_3() {
//	set_flag_alu_3.execute_stateful_alu(0);
//}
table set_flag_three_t {
	actions {temp_pktcnt_subtract_min_value;}
	default_action: temp_pktcnt_subtract_min_value;
}

//register flag_4 {
//	width: 32;
//	instance_count: 1;
//}
//blackbox stateful_alu compare_digest {
//	reg: flag_4;
//	condition_lo: measurement_meta.digest == measurement_meta.current_digest;
//	update_lo_1_predicate: condition_lo;
//	update_lo_1_value: 1;
//	update_lo_2_predicate: not condition_lo;
//	update_lo_2_value: 0;
//	output_value: alu_lo;
//	output_dst: measurement_meta.flag_same_digest;
//}

action _nop() {
}

action set_status() {
	modify_field(measurement_meta.status, 1);
}

table set_status_t_1 {
	reads {measurement_meta.promotion: exact;}
	actions {set_status;}
	default_action: set_status;
}
table set_status_t_2 {
	reads {measurement_meta.promotion: exact;}
	actions {set_status;}
	default_action: set_status;
}
table set_status_t_3 {
	reads {measurement_meta.promotion: exact;}
	actions {set_status;}
	default_action: set_status;
}

action update_min_1() {
	record_flow_pktcnt_one_alu.execute_stateful_alu_from_hash(main_hash_1);
//	record_flow_pktcnt_one_alu.execute_stateful_alu(measurement_meta.m_idx_1);
//	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_1);
}

action update_min_2() {
	modify_field(measurement_meta.min_value, measurement_meta.pktcnt);
//	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_2);
}

action update_min_3() {
	modify_field(measurement_meta.min_value, measurement_meta.pktcnt);
//	modify_field(measurement_meta.min_idx, measurement_meta.m_idx_3);
}

//action pkt_xor_temp() {
//	bit_xor(measurement_meta.srcip, measurement_meta.srcip, ipv4.srcip);	
//	bit_xor(measurement_meta.dstip, measurement_meta.dstip, ipv4.dstip);
//	bit_xor(measurement_meta.srcport, measurement_meta.srcport, tcp.srcport);
//	bit_xor(measurement_meta.dstport, measurement_meta.dstport, tcp.dstport);
//	bit_xor(measurement_meta.prot, measurement_meta.prot, ipv4.proto);
//}

//action main_idx_one_calc () {
//	modify_field_with_hash_based_offset(measurement_meta.m_idx_1, 0, 
//		main_hash_1, SUB_TABLE_A_SIZE);
//	modify_field_with_hash_based_offset(measurement_meta.m_idx_2, 
//		0, main_hash_2, SUB_TABLE_B_SIZE);
//	modify_field_with_hash_based_offset(measurement_meta.m_idx_3, 
//		0, main_hash_3, SUB_TABLE_C_SIZE);
//	modify_field_with_hash_based_offset(measurement_meta.current_digest, 0,
//		digest_hash, 256);
//}
//action main_idx_two_calc () {
//	modify_field_with_hash_based_offset(measurement_meta.m_idx_2, 
//		0, main_hash_2, SUB_TABLE_B_SIZE);
//}
//action main_idx_three_calc () {
//	modify_field_with_hash_based_offset(measurement_meta.m_idx_3, 
//		0, main_hash_3, SUB_TABLE_C_SIZE);
//	modify_field_with_hash_based_offset(measurement_meta.a_idx,0, 
//		ancillary_hash, ANCILLARY_TABLE_SIZE);
//}
//action ancillary_idx_calc () {
//	modify_field_with_hash_based_offset(measurement_meta.a_idx,0, 
//		ancillary_hash, ANCILLARY_TABLE_SIZE);
//}
action digest_calc () {
	modify_field_with_hash_based_offset(measurement_meta.current_digest, 0,
		digest_hash, 256);
}

//table main_idx_one_calc_t {
//	actions {main_idx_one_calc;}
//	default_action: main_idx_one_calc;
//}
//table main_idx_two_calc_t {
//	actions {main_idx_two_calc;}
//	default_action: main_idx_two_calc;
//}
//table main_idx_three_calc_t {
//	actions {main_idx_three_calc;}
//	default_action: main_idx_three_calc;
//}
//table ancillary_idx_calc_t {
//	actions {ancillary_idx_calc;}
//	default_action: ancillary_idx_calc;
//}
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

//action digest_subtraction () {
//	subtract_from_field(measurement_meta.digest, 
//		measurement_meta.current_digest);
//	compare_digest.execute_stateful_alu(0);
//}
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

/*table compare_for_empty_one_t {
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

//table compare_for_matching_two_t {
//	reads {
//		measurement_meta.srcip: exact;
//		measurement_meta.dstip: exact;
//		measurement_meta.srcport: exact;
//		measurement_meta.dstport: exact;
//		measurement_meta.prot: exact;
//	}
//	actions {
//		set_status;
//		set_flag_1;
//	}
//	default_action: set_flag_1;
//}

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
}*/

//table read_ancillary_data_t {
//	actions {
//		read_ancillary_table;
//	}
//}

//table ancillary_compare_for_empty_t {
//	reads {
//		measurement_meta.digest: exact;
//	}
//	actions {
//		set_one_temp_pktcnt;
//		_nop;
//		digest_subtraction;
//	}
//	default_action: digest_subtraction;
//	size: 256;
//}

//table ancillary_compare_for_matching_t {
//	reads {
//		measurement_meta.digest: exact;
//		measurement_meta.flag_same_digest: exact;
//	}
//	actions {
//		set_one_temp_pktcnt;
//		_nop;
//		set_flag_2;
//	}
//	default_action: _nop;
//	size: 256;		
//}

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
	reads {
		measurement_meta.flag mask 0x80000000: exact;
	}
	actions {
		update_min_2;
	}
	default_action: update_min_2;
	size: 2;
}

table update_min_three_t {
	reads {
		measurement_meta.flag mask 0x80000000: exact;
	}
	actions {
		update_min_3;
	}
	default_action: update_min_3;
	size: 2;
}

//table promotion_t {
//	actions {
//		promote;
//	}
//	default_action: promote;
//}

// the width of resubmit fields cannot exceeds 42 bits
field_list resubmit_fields_1 {
	measurement_meta.stage;
	measurement_meta.promotion;
	measurement_meta.min_value;
//	measurement_meta.status;
//	measurement_meta.temp;
}
field_list resubmit_fields_2 {
	measurement_meta.stage;
	measurement_meta.promotion;
	measurement_meta.temp_pktcnt;
}
field_list resubmit_fields {
	measurement_meta.stage;
	measurement_meta.promotion;
}

action do_resubmit() {
	add_to_field(measurement_meta.stage, 1);
    resubmit(resubmit_fields);
//	resubmit();
}

action do_resubmit_1() {
	modify_field(measurement_meta.stage, 1);
	resubmit(resubmit_fields_1);
}
action do_resubmit_2() {
	modify_field(measurement_meta.stage, 2);
	resubmit(resubmit_fields_1);
}
action do_resubmit_3() {
	modify_field(measurement_meta.stage, 3);
	resubmit(resubmit_fields_1);
}
action do_resubmit_4() {
	modify_field(measurement_meta.stage, 1);
	resubmit(resubmit_fields_2);
}
action do_resubmit_5() {
	modify_field(measurement_meta.stage, 2);
	resubmit(resubmit_fields_2);
}
action do_resubmit_6() {
	modify_field(measurement_meta.stage, 3);
	resubmit(resubmit_fields_2);
}
table do_resubmit_t {
    reads {
        measurement_meta.status: exact;
		measurement_meta.promotion: exact;
		measurement_meta.flow_table_no: exact;
    }
    actions {
        _nop;
        do_resubmit_1;
		do_resubmit_2;
		do_resubmit_3;
		do_resubmit_4;
		do_resubmit_5;
		do_resubmit_6;
    }
    size : 12;
}

// debug
header_type temp_meta_t {
	fields {
		n_pkts: 32;
		n_hashes: 32;
		n_mem_access: 32;
	}
}
metadata temp_meta_t temp_meta;

//control idx_and_digest_calc {
//	apply(main_idx_one_calc_t);
//	apply(main_idx_two_calc_t);
//	apply(main_idx_three_calc_t);
//	apply(ancillary_idx_calc_t);
//	apply(digest_calc_t);
//}

control read_main_data_1 {
//	apply(m_table);
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
