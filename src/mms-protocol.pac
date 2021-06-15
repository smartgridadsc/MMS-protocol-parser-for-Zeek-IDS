# This is where the message formats are defined
%include mms-asn1.pac
%include mms-tags.pac

type MMS_PDU(is_orig: bool) = record {
	t: tpkt(is_orig); 
	c: cotp(t.length);
	s: session;
	p: presentation (c.eot_bit);
	m: mms;
}&byteorder=bigendian;

# Defined in RFC 1006
type tpkt(is_orig: bool) = record {
	version: uint8;
	reserved: uint8;
	length: uint16;
}&let {
	proc: bool = $context.flow.proc_tpkt(this);
	is_request: bool = $context.flow.update_is_request(is_orig);
};

# For long packets that are segmented, the initial packet will contain the layers up to L7 (presentation + partial mms).
# Subsequent packets will contain only tpkt, cotp, and arbitrary remainder of previous packet.
# Therefore, at cotp layer, we check if this is a "remainder" packet (2nd in sequence onwards) and store the fragment.
# If this packet is the last fragment, we reassemble it and cast the contents to a new MMS PDU.
type cotp(tpkt_length:uint16) = record {
	len: uint8;
	body: uint8[len]; #0xf0-> data, second byte first bit-> EOT
	fragment: bytestring &length=(is_fragment?tpkt_length-7:0); #offset by 7 for tpkt/cotp headers
}&let {
	proc: bool = $context.flow.proc_cotp(this);
	
	# Store if eot_bit is set and this is not the 1st fragment. 1st fragment will be stored in L7.
	eot_bit: bool = $context.flow.proc_cotp_set_eot_bit(this);
	is_fragment: bool = $context.flow.proc_cotp_get_in_fragment();
	store_fragment: bool = $context.flow.proc_store_fragment(fragment) &if is_fragment;
	
	# Last fragment. Perform reassembly for MMS PDU.
	is_end_fragment: bool = is_fragment&&eot_bit;
	reassembled: bytestring = $context.flow.proc_cotp_reassembled() &if is_end_fragment;
	parse_reassembled: mms withinput reassembled &if is_end_fragment;
};

type session = record {
	spdu_type: uint8; 	#1=data, #13=connect, #14=accept, others=non-mms
	len: uint8;			#len>=0 for connect/accept. len=0 for data

	body: case spdu_type of {
		SPDU_DATA 		-> a: spdu_data_record;
		SPDU_CONNECT 	-> b: spdu_connect_record;
		SPDU_ACCEPT 	-> c: spdu_accept_record;
	};
}&let {
	proc: bool = $context.flow.proc_session(this);
};

# When SPDU is of type data, 'Give tokens PDU' is concatenated with 'Data Transfer SPDU'.
# Do not parse the entire ASN1Encoding contents as this encapsulates mms for all SPDU types
type spdu_data_record=record{
	body: uint8[2];
};

# Parse data until the specific tag for Session User Data which encapsulates ACSE/MMS
type spdu_connect_record=record{
	a: spdu_encoding[] &until($element.tag==193); # Session User Data tag
};

type spdu_accept_record=record{
	a: spdu_encoding[] &until($element.tag==193); # Session User Data tag
};

# Special case where tag, len are 1 byte each
type spdu_encoding=record{
	tag: uint8;
	len: uint8;
	data: case tag of {
		193      -> none: empty; # Session User Data tag
		default  -> content: bytestring &length=len;
	};
};

# For connect/accept packets, ACSE layer follows after the presentation layer.
# For data packets, mms layer follows.
type presentation(eot_bit: bool) = record {
	meta: ASN1EncodingMeta; #0x31 (49) for connect/accept or 0x61 (97) for data
	
	body: case meta.tag of {
		PRES_CONNECT	-> a: presentation_connect_record;
		PRES_DATA		-> b: presentation_data_record(eot_bit, in_fragment);
	} &requires(in_fragment); #requires is needed to work around a binpac bug.
}&let {
	proc: bool = $context.flow.proc_presentation(this);
	in_fragment: bool = $context.flow.proc_presentation_set_in_fragment();
};

type presentation_connect_record = record
{
	mode_selector: ASN1Encoding; #tag 0xa0
	normal_mode_meta: ASN1EncodingMeta; #tag 0xa2
	normal_mode_optionals: presentation_skip_to_tag[] &until($element.meta.tag==0x61); #fully-encoded-data
	pdv_list_meta: ASN1EncodingMeta; #sequence tag 0x30
	
	#next field is optional transfer-syntax-name or non-optional presentation-context-identifier
	optional_meta: ASN1EncodingMeta;
	optional_data: case transfer_syntax_name_present of {
		true   -> a: bytestring &length=optional_meta.length;
		false  -> b: empty;
	};
	
	#if optional field is present, this field will be populated. otherwise remains empty.
	presentation_context_identifier_meta: ASN1OptionalEncodingMeta(transfer_syntax_name_present, optional_meta);
	presentation_context_identifier_data: bytestring &length=transfer_syntax_name_present?presentation_context_identifier_meta.length:optional_meta.length;
	
	presentation_data_values_meta: ASN1EncodingMeta;
	aarq_aare: acse_record;
	
}&let{
	transfer_syntax_name_present: bool = optional_meta.tag==0x06;
};

type acse_record = record
{
	aarq_aare_meta: ASN1EncodingMeta; #0x60 / 0x61
	aarq_aare_optionals: acse_skip_to_tag_user_information[] &until($element.meta.tag==0xbe);
	
	external_meta: ASN1EncodingMeta;
	
	#Another set of optionals to skip and remainder will be mms payload
	optionals: acse_skip_to_tag_external_encoding[] &until($element.meta.tag!=0x06 && $element.meta.tag!=0x02 && $element.meta.tag!=0x07);	
};

type acse_skip_to_tag_user_information = record
{
	meta: ASN1EncodingMeta;
	data: case meta.tag of {
		0xbe     -> none: empty; # user-information
		default  -> content: bytestring &length=meta.length;
	};
};

type acse_skip_to_tag_external_encoding = record
{
	meta: ASN1EncodingMeta;
	data: case meta.tag of {
		0x06  -> direct_reference: bytestring &length=meta.length;
		0x02  -> indirect_reference: bytestring &length=meta.length;
		0x07  -> data_value_descriptor: bytestring &length=meta.length;
		default -> none: empty; #should be field external::encoding
	};
}

type presentation_skip_to_tag = record
{
	meta: ASN1EncodingMeta;
	data: case meta.tag of {
		0x61     -> none: empty; # fully-encoded-data
		default  -> content: bytestring &length=meta.length;
	};
};

# In this layer, we store MMS data contents for fragmented packets. If it is complete, the flow will continue to the MMS PDU. 
type presentation_data_record(eot_bit: bool, in_fragment: bool) = record
{
	 pdv_meta: ASN1EncodingMeta; # 0x30
	 body: uint8[3]; #todo: check this. seems to be fixed: presentation-context tag 0x02, length, mms annex version1 0x03
	 single_asn1_meta: ASN1EncodingMeta;
	 fragment: optional_fragment(in_fragment);

}&let {
	proc: bool = $context.flow.proc_presentation_data_record(this);
	
	# At this point either store fragment or parse full packet
	store_fragment = $context.flow.proc_store_fragment(fragment.data) &if in_fragment;
};

type optional_fragment(in_fragment: bool) = case in_fragment of
{
	true  -> data: bytestring &restofdata;
	false -> none: empty;
};

# ========================= MMS =========================

type mms = record{
	meta: ASN1EncodingMeta;
	
	body: case meta.tag of {
		MMS_CONFIRMED_REQ_PDU	-> a: mms_confirmed_req_pdu_record;
		MMS_CONFIRMED_RES_PDU	-> b: mms_confirmed_res_pdu_record;
		#MMS_CONFIRMED_ERROR_PDU-> c: mms_confirmed_error_pdu_record;
		MMS_INITIATE_REQ_PDU	-> i: mms_initiate_req_pdu_record;
		MMS_INITIATE_RES_PDU	-> j: mms_initiate_res_pdu_record;
		
		MMS_CANCEL_REQ_PDU		-> k: mms_cancel_pdu_record;
		MMS_CANCEL_RES_PDU		-> l: mms_cancel_pdu_record;
		
		MMS_CONCLUDE_REQ_PDU	-> m: empty; #NULL in protocol
		MMS_CONCLUDE_RES_PDU	-> n: empty; #NULL in protocol
		##MMS_CONCLUDE_ERR_PDU	-> o: bytestring &restofdata;
		
		default                 -> unknown: bytestring &restofdata; 
	};	
	
}&let {
	proc: bool = $context.flow.proc_mms(this);
	generic_event_generation: bool = $context.flow.generic_event_generator();
};

#============ MMS INITIATE PDU =================

type mms_initiate_req_pdu_record = record {
	body: mms_initiate_record;
} &let {
	proc: bool = $context.flow.proc_mms_initiate_req_pdu(body);
};

type mms_initiate_res_pdu_record = record {
	body: mms_initiate_record;
} &let {
	proc: bool = $context.flow.proc_mms_initiate_res_pdu(body);
}

type mms_initiate_record = record
{
	# field_1 (localDetailCalling/localDetailCalled) is optional. Fields 1-2 or 1-3 will be populated accordingly. All ints.
	field_1: ASN1Encoding;
	field_2: ASN1Encoding;
	field_3: case field_1_present of {
		true  -> field_3_data: ASN1Encoding;
		false -> field_3_none: empty;
	};
	
	# field_4 (request:proposedDataStructureNestingLevel/response:negotiatedDataStructureNestingLevel) is optional
	field_4_meta: ASN1EncodingMeta;
	field_5: case field_4_present of {
		true  -> field_4_data: bytestring &length=field_4_meta.length;
		false -> field_4_none: empty;
	};
	
	# meta will be stored in field_4_meta or init_request_detail_meta / init_response_detail_meta
	init_detail_meta: ASN1OptionalEncodingMeta(field_4_present, field_4_meta);
	
	version_number: ASN1Encoding;#int proposedVersionNumber or negotiatedVersionNumber
	parameter_cbb: ASN1Encoding; #bitstring proposedParameterCBB or negotiatedParameterCBB
	services_supported_call: ASN1Encoding; #bitstring servicesSupportedCalling or servicesSupportedCalled
	
	# currently not stored as it has not been tested. header is printed.
	additional_parameters: bytestring &restofdata;
	
} &let {
	field_1_present: bool = field_1.meta.tag==0x80; #localDetailCalling
	field_4_present: bool = field_4_meta.tag==0x83; #proposedDataStructureNestingLevel
	additional_parameters_parsing: bool = $context.flow.proc_mms_initiate_additional_params(additional_parameters);
};

#============ MMS CANCEL PDU =================

type mms_cancel_pdu_record = record {
	body: uint32;
}&byteorder=bigendian, &let { #TODO: is it big endian or little?
	proc: bool = $context.flow.proc_mms_cancel_pdu(this);
};

#============ MMS CONFIRMED REQUEST PDU =================

type mmsASN1Encoding = record {
	meta:    mmsASN1EncodingMeta;
	content: bytestring &length = meta.length;
};

type mmsASN1EncodingMeta = record {
	low_tag	: uint8;
	more_tag: bytestring &length = long_tag ? 1 : 0;
	len		: uint8;
	more_len: bytestring &length = long_len ? len & 0x7f : 0;
} &let {
	long_tag		: bool = low_tag == 0x9f || low_tag == 0xbf;
	long_len        : bool = (len & 0x80) > 0;
	tag				: uint64 = long_tag ? binary_to_int64(more_tag) : low_tag;
	length			: uint64 = long_len ? binary_to_int64(more_len) : len;
	index           : uint8 = low_tag - ASN1_INDEX_TAG_OFFSET;
};

type mmsASN1OptionalEncodingMeta(is_present: bool, previous_metadata: mmsASN1EncodingMeta) = case is_present of {
	true  -> data: mmsASN1EncodingMeta;
	false -> none: empty;
} &let {
	length: uint64 = is_present ? data.length : previous_metadata.length;
	tag: uint64 = is_present? data.tag : previous_metadata.tag;
};

type mms_confirmed_req_pdu_record = record {

	invoke_id: ASN1Encoding; # Tag starts with 0x02 

	meta: mmsASN1EncodingMeta;
	list_of_modifiers: optional_list_of_modifiers(list_of_modifiers_present, meta.length);
	next_meta: mmsASN1OptionalEncodingMeta(list_of_modifiers_present, meta);
	confirmed_service_request: mms_confirmed_service_request(csr_tag, csr_length);
} &let {
	list_of_modifiers_present: bool = meta.tag == 0x02;
	csr_tag: uint64 = list_of_modifiers_present? next_meta.data.tag: meta.tag;
	csr_length: uint64 = list_of_modifiers_present? next_meta.data.length: meta.length;
	proc: bool = $context.flow.proc_mms_confirmed_req_pdu(this);
};

type mms_confirmed_service_request(tag: uint64, length: uint64) = case tag of {
	MMS_SERVICE_REQ_STATUS						-> a: uint8;
	MMS_SERVICE_REQ_GET_NAME_LIST 				-> b: mms_confirmed_req_get_name_list_record(length);
	MMS_SERVICE_REQ_IDENTIFY					-> c: empty;
	MMS_SERVICE_REQ_RENAME						-> d: mms_confirmed_req_rename_record;
	MMS_SERVICE_REQ_READ						-> e: mms_confirmed_req_read_record;
	MMS_SERVICE_REQ_WRITE						-> f: mms_confirmed_req_write_record;
	MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR			-> g: mms_confirmed_req_get_var_access_attr_record;
	#MMS_SERVICE_REQ_DEFINE_NAMED_VAR			-> h: mms_confirmed_req_define_named_var_record;
	MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST		-> l: mms_confirmed_req_define_named_var_list_record;
	MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR	 	-> m: mms_confirmed_req_get_named_var_list_attr_record;
	MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST		-> n: mms_confirmed_req_delete_named_var_list_record(delete_named_present, length);
	MMS_SERVICE_REQ_OBTAIN_FILE					-> au: mms_confirmed_req_obtain_file_record;
	MMS_SERVICE_REQ_READ_JOURNAL				-> bn: mms_confirmed_req_read_journal_record(length);
	MMS_SERVICE_REQ_FILE_OPEN					-> bu: mms_confirmed_req_file_open_record;
	MMS_SERVICE_REQ_FILE_READ					-> bv: bytestring &restofdata; #TODO: this is int32. byteorder to be tested before &let.
	MMS_SERVICE_REQ_FILE_CLOSE					-> bw: bytestring &restofdata; #TODO: same as above
	MMS_SERVICE_REQ_FILE_RENAME					-> bx: mms_confirmed_req_file_rename_record;
	MMS_SERVICE_REQ_FILE_DELETE					-> by: ASN1Encoding;
	MMS_SERVICE_REQ_FILE_DIRECTORY				-> bz: mms_confirmed_req_file_directory_record(file_dir_present, length);
	default										-> unknown: bytestring &restofdata;
} &requires(file_dir_present, delete_named_present) &let {
	file_dir_present: bool = length > 0;
	delete_named_present: bool = length > 0;
	proc: bool = $context.flow.proc_mms_confirmed_service_request(this);
};

type optional_list_of_modifiers(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: mms_list_of_modifiers[] &until($element.last) &length=length;
	false 	-> none: empty;
};

type mms_list_of_modifiers = record {
	meta: ASN1EncodingMeta;
	args: mms_modifiers &length= arg_length;
} &let {
	last: bool = meta.tag == 0xa0 || 0xa1 || 0xa2 || 0xa3;
	arg_length: uint64 = (last ? 0 : meta.length);
};

type mms_modifiers = record {
	modifierID : ASN1Integer;

	meta: ASN1EncodingMeta;
	body: case meta.tag of {
		0x80 	-> a: bytestring &restofdata; #notcomplete
		0x81	-> b: bytestring &restofdata; #notcomplete
		default	-> unknown: bytestring &restofdata;
	};
};

#============ MMS CONFIRMED RESPONSE PDU =================

type mms_confirmed_res_pdu_record = record {
	invoke_id					: ASN1Encoding;
	confirmed_service_response	: mms_confirmed_service_response;
} &let {
	#TODO: executed after decoding fields. setting intermediate global fields here does not help. check other global fields.
	proc: bool = $context.flow.proc_mms_confirmed_res_pdu(this);
};
	
type mms_confirmed_service_response = record {
	meta: mmsASN1EncodingMeta;
	body: case meta.tag of{
		MMS_SERVICE_RES_STATUS						-> a: mms_status_response(meta.length);
		MMS_SERVICE_RES_GET_NAME_LIST 				-> b: mms_confirmed_res_get_name_list_record;
		MMS_SERVICE_RES_IDENTIFY					-> c: mms_confirmed_res_identify_record(meta.length);
		MMS_SERVICE_RES_RENAME						-> d: ASN1Encoding;
		MMS_SERVICE_RES_READ						-> e: mms_confirmed_res_read_record;
		MMS_SERVICE_RES_WRITE						-> f: mms_confirmed_res_write_record;
		MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR			-> g: mms_confirmed_res_get_var_access_attr_record(meta.length);
		# MMS_SERVICE_RES_DEFINE_NAMED_VAR			-> h: mms_confirmed_res_define_named_var_record;
		MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST		-> l: empty;
		MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR 	-> m: mms_confirmed_res_get_named_var_list_attr_record(meta.length); # added length
		MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST		-> n: mms_confirmed_res_delete_named_var_list_record;
		MMS_SERVICE_RES_OBTAIN_FILE					-> au: empty;
		MMS_SERVICE_RES_READ_JOURNAL				-> bn: mms_confirmed_res_read_journal_record;
		MMS_SERVICE_RES_FILE_OPEN					-> bu: mms_confirmed_res_file_open_record;
		MMS_SERVICE_RES_FILE_READ					-> bv: mms_confirmed_res_file_read_record;
		MMS_SERVICE_RES_FILE_CLOSE					-> bw: empty;
		MMS_SERVICE_RES_FILE_RENAME					-> bx: empty;
		MMS_SERVICE_RES_FILE_DELETE					-> by: empty;
		MMS_SERVICE_RES_FILE_DIRECTORY				-> bz: mms_confirmed_res_file_directory_record;
		default                       				-> unknown: bytestring &restofdata; 
	};	
} &let {
	proc: bool = $context.flow.proc_mms_confirmed_service_response(this);
};

#=========== MMS CONFIRMED REQUEST SERVICES ==============

type mms_confirmed_req_get_name_list_record(length: uint64) = record {
	object_class_meta: ASN1EncodingMeta;
	object_class: mms_object_class;
	object_scope_meta: ASN1EncodingMeta;
	object_scope: mms_object_scope;
	continue_after: case continue_after_present of { #OPTIONAL
		true	-> data: mms_identifier;
		false	-> none: empty;
	};
} &let {
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, object_class_meta);
	continue_after_present: bool = $context.flow.proc_mms_remaining_check(r1, object_scope_meta);
};

type mms_confirmed_req_rename_record = record {
	object_class_meta: ASN1EncodingMeta;
	object_class: mms_object_class;
	current_name_meta: ASN1EncodingMeta;
	current_name: mms_object_name;
	new_id: ASN1Encoding;
}

type mms_confirmed_req_read_record = record {
	spec_with_result_meta: ASN1EncodingMeta; #0x80
	spec_with_result: optional_spec_with_result(spec_with_result_present);
	next_meta: ASN1OptionalEncodingMeta(spec_with_result_present, spec_with_result_meta);
	variable_access_spec: mms_variable_access_spec_meta;
} &let {
	spec_with_result_present: bool = spec_with_result_meta.tag==0x80;
	variable_access_spec_tag: uint8 = spec_with_result_present? next_meta.data.tag: spec_with_result_meta.tag;
	variable_access_spec_length: uint64 = spec_with_result_present? next_meta.data.length: spec_with_result_meta.tag;
	proc: bool = $context.flow.proc_mms_confirmed_req_read_record(this);
};

type mms_confirmed_req_write_record = record {
	variable_access_spec_meta: ASN1EncodingMeta;
	variable_access_spec: mms_variable_access_spec(variable_access_spec_meta.tag, 
		variable_access_spec_meta.length) &length=variable_access_spec_meta.length;
	list_of_data_meta: ASN1EncodingMeta;
	list_of_data: mms_list_of_data;
};

type mms_confirmed_req_get_var_access_attr_record = record {
	meta: ASN1EncodingMeta;
	body: case meta.tag of {
		0xa0		-> object_name: mms_object_name;
		0xa1	 	-> address: mms_address;
		default	 	-> unknown: bytestring &restofdata;
	};
};

type mms_confirmed_req_define_named_var_list_record = record {
	variable_list_name: mms_object_name;
	list_of_variable_meta: ASN1EncodingMeta;
	list_of_variable: mms_list_of_variables_items[];
};

type mms_confirmed_req_get_named_var_list_attr_record = record {
	object_name: mms_object_name;
};

type mms_confirmed_req_delete_named_var_list_record(is_present: bool, length: uint64) = case is_present of {
	true	-> data: mms_delete_named_var_list(length);
	false	-> none: empty;
};

type mms_delete_named_var_list(length: uint64) = record {
	first_meta: ASN1EncodingMeta;
	scope_of_delete: optional_scope(scope_present);
	second_meta: ASN1OptionalEncodingMeta(second_meta_present, first_meta);
	list_of_var: optional_list_of_var_list_name(list_present);
	third_meta: ASN1OptionalEncodingMeta(third_meta_present, second_meta.data);
	domain_name: optional_domain_name(domain_name_present) &requires(store_scope_of_delete);
} &let {
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, first_meta);
	r2: uint64 = $context.flow.proc_mms_remaining_length(r1, second_meta.data);
	second_meta_present: bool = r1 > 0;
	third_meta_present: bool = r2 > 0;
	scope_present: bool = first_meta.tag == 0x80;
	list_present: bool = scope_present? second_meta.data.tag==0xa1 : first_meta.tag==0xa1;
	tmp1: bool = first_meta.tag==0xa1? second_meta.data.tag==0xa2 : first_meta.tag==0xa2;
	tmp2: bool = scope_present && second_meta.data.tag == 0xa2;
	domain_name_present: bool = tmp1 || tmp2 || third_meta_present;
	store_scope_of_delete: bool = $context.flow.proc_mms_delete_named_var_list(scope_present, scope_of_delete) &requires(scope_of_delete);
};

type mms_confirmed_req_obtain_file_record = record {
	meta: ASN1EncodingMeta;
	source_file_server: optional_source_file_server(server_present, meta.length);
	next_meta: ASN1OptionalEncodingMeta(server_present, meta);
	source_file: ASN1Encoding; #GraphicString
	destination_file_meta: ASN1EncodingMeta;
	destination_file: ASN1Encoding; #GraphicString
} &let {
	server_present: bool = meta.tag == 0xa0;
};

# TODO: Implementation for readJournal service is incomplete
type mms_confirmed_req_read_journal_record(length: uint64) = record {
	journal_name_meta: ASN1EncodingMeta;
	journal_name: mms_object_name;
	optional: optional_read_journal(optionals_present, optionals_length);
} &requires(optionals_present, optionals_length) &let {
	optionals_length: uint64 = $context.flow.proc_mms_remaining_length(length,journal_name_meta);
	optionals_present: bool = optionals_length > 0;
};

type optional_read_journal(is_present: bool, length: uint64) = case is_present of {
	true	-> data: optional_req_read_journal(length);
	false 	-> none: empty;
};

type optional_req_read_journal(length: uint64) = record {
	first_meta: ASN1EncodingMeta;
	start: optional_range_start_spec(start_present);
	second_meta: ASN1OptionalEncodingMeta(second_meta_present, first_meta);
	stop: optional_range_stop_spec(stop_present);
	third_meta: ASN1OptionalEncodingMeta(third_meta_present, second_meta.data);
	list: optional_list_of_var(list_present, list_length);
	fourth_meta: ASN1OptionalEncodingMeta(fourth_meta_present, third_meta.data); #entryToStartAfter
	entry: optional_entry_to_start_after(entry_present);
} &let {
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, first_meta);
	r2: uint64 = $context.flow.proc_mms_remaining_length(r1, second_meta.data);
	r3: uint64 = $context.flow.proc_mms_remaining_length(r2, third_meta.data);
	second_meta_present: bool = r1 > 0;
	third_meta_present: bool = r2 > 0;
	fourth_meta_present: bool = r3 > 0;

	start_present: bool = first_meta.tag == 0xa1;
	stop_present: bool = start_present? second_meta.data.tag==0xa2 : first_meta.tag==0xa2;
	list_tmp1: bool = second_meta_present? second_meta.data.tag==0xa4 : 0;
	list_tmp2: bool = third_meta_present? third_meta.data.tag==0xa4 : 0;
	list_present: bool = first_meta.tag==0xa4 || list_tmp1 || list_tmp2;
	entry_tmp1: bool = second_meta_present? second_meta.data.tag==0xa5 : 0;
	entry_tmp2: bool = third_meta_present? third_meta.data.tag==0xa5 : 0;
	entry_tmp3: bool = fourth_meta_present? fourth_meta.data.tag==0xa5 : 0;
	entry_present: bool = first_meta.tag==0xa5 || entry_tmp1 || entry_tmp2 || entry_tmp3;

	l1: uint64= first_meta.tag==0xa4? first_meta.length : 0;
	l2: uint64= list_tmp1? second_meta.length : l1;
	l3: uint64= list_tmp2? third_meta.length : l2;
	list_length: uint64 = l1 || l2 || l3;
};

type mms_confirmed_req_file_open_record = record {
	file_name_meta: ASN1EncodingMeta;
	file_name: ASN1Encoding; #GraphicString
	initial_position: ASN1Encoding;
};

type mms_confirmed_req_file_rename_record = record {
	current_file_meta: ASN1EncodingMeta;
	current_file: ASN1Encoding; #GraphicString
	new_file_meta: ASN1EncodingMeta;
	new_file: ASN1Encoding; #GraphicString
};

type mms_confirmed_req_file_directory_record(is_present: bool, length: uint64) = case is_present of {
	true	-> data: mms_file_directory(length) &length = length;
	false	-> none: empty;
};

type mms_file_directory(length: uint64) = record {
	first_meta: ASN1EncodingMeta;
	file_spec: optional_file_name(file_spec_present);
	second_meta: ASN1OptionalEncodingMeta(second_meta_present, first_meta);
	continue_after: optional_file_name(continue_after_present);
} &let {
	proc: bool = $context.flow.proc_mms_file_directory(this);
	file_spec_present: bool = first_meta.tag == 0xa0;
	second_meta_present: bool = file_spec_present && $context.flow.proc_mms_remaining_check(length, first_meta);
	continue_after_present: bool = file_spec_present? second_meta_present && second_meta.data.tag==0xa1 : first_meta.tag==0xa1;
};

type optional_scope(is_present: bool) = case is_present of {
	true	-> data: uint8; #TODO check if INTEGER is uint8
	false	-> none: empty;
};

type optional_list_of_var_list_name(is_present: bool) = case is_present of {
	true 	-> data: mms_object_name;
	false	-> none: empty;
};

type optional_domain_name(is_present: bool) = case is_present of {
	#true	-> data: bytestring &restofdata;
	true	-> data: mms_identifier;
	false	-> none: empty;
};

type optional_identifier(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: bytestring &restofdata;
	false	-> none: empty;
};

type optional_spec_with_result(is_present: bool) = case is_present of {
	true 	-> data: uint8;
	false	-> none: empty;
};

type optional_source_file_server(is_present: bool, length: uint64) = case is_present of {
	#TODO: ApplicationReference
	true -> data: bytestring &length=length; 
	false -> none: empty;
};

type optional_range_start_spec(is_present: bool) = case is_present of {
	true 	-> data: ASN1Encoding;
	false	-> none: empty;
};

type optional_range_stop_spec(is_present: bool) = case is_present of {
	true 	-> data: ASN1Encoding;
	false	-> none: empty;
};

type optional_list_of_var(is_present: bool, length: uint64) = case is_present of {
	true	-> data: ASN1Encoding[] &length=length;
	false	-> none: empty;
};

type optional_entry_to_start_after(is_present: bool) = case is_present of {
	true	-> data: ASN1Encoding;
	false	-> none: empty;
};

type optional_file_name(is_present: bool) = case is_present of {
	true	-> data: ASN1Encoding; #fileName
	false	-> none: empty;
};

#=========== MMS CONFIRMED RESPONSE SERVICES ==============

type mms_confirmed_res_get_name_list_record = record {
	list_of_identifiers_meta: ASN1EncodingMeta;
	list_of_identifiers: ASN1Encoding[] &length=list_of_identifiers_meta.length; 
	more_follows: bytestring &restofdata; #Boolean
} &let {
	# store in map 
	proc: bool = $context.flow.proc_mms_confirmed_res_get_name_list_record(this);
};

type mms_confirmed_res_identify_record(length: uint64) = record {
	vendor_name: ASN1Encoding;
	model_name: ASN1Encoding;
	revision: ASN1Encoding;
	list_abs_syntax: case abs_syntax_present of {
		true -> data: optional_list_abs_syntax;
		false -> none: empty;
	};
} &let {
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, vendor_name.meta);
	r2: uint64 = $context.flow.proc_mms_remaining_length(r1, model_name.meta);
	r3: uint64 = $context.flow.proc_mms_remaining_length(r2, revision.meta);
	abs_syntax_present: bool = r3 > 0;
};

type mms_confirmed_res_read_record = record {
	variable_access_spec_meta: ASN1EncodingMeta;
	variable_access_spec: optional_variable_access_spec(variable_access_spec_present, variable_access_spec_meta.length);
	next_meta: ASN1OptionalEncodingMeta(variable_access_spec_present, variable_access_spec_meta);
	access_result: mms_access_result(access_result_tag)[];
} &let {
	variable_access_spec_present: bool = variable_access_spec_meta.tag==0xa0;
	access_result_tag: uint8 = variable_access_spec_present? next_meta.data.tag: variable_access_spec_meta.tag;
};

type mms_access_result(tag: uint8) = case tag of {
	0xa0	-> failure: mms_data_access_error;
	0xa1	-> success: mms_list_of_data;
};

type mms_confirmed_res_write_record = record {
	meta: ASN1EncodingMeta;
	body: case meta.tag of {
		0x80	-> failure: mms_data_access_error;
		0x81	-> success: empty;
		default	-> unknown: bytestring &restofdata;
	};
};

type mms_confirmed_res_get_var_access_attr_record(length: uint64) = record {
	mms_deletable: ASN1Encoding;
	address_meta: ASN1EncodingMeta; #&requires(store_mms_deletable);
	address	: optional_address(address_present, address_meta.length) &requires(store_mms_deletable);
	next_meta: ASN1OptionalEncodingMeta(address_present, address_meta);
	type_description: mms_type_description;
	optional: case optionals_present of {
		true 	-> data: optional_res_get_var_access_attr(optionals_length);
		false	-> none: empty;
	} &requires(optionals_length);
} &let {
	store_mms_deletable: bool = $context.flow.proc_mms_confirmed_res_get_var_access_attr_record(this);
	
	address_present: bool = address_meta.tag==0x81;
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, mms_deletable.meta);
	r2: uint64 = $context.flow.proc_mms_remaining_length(r1, address_meta);
	r3: uint64 = r2 > 0 ? $context.flow.proc_mms_remaining_length(r2, next_meta.data) : 0;
	optionals_present: bool = r3 > 0;
	optionals_length: uint64 = address_present? r3 : r2;
};

type optional_res_get_var_access_attr(length: uint64) = record {
	first_meta: ASN1EncodingMeta;
	access: optional_access_control_list(access_present, first_meta.length);
	second_meta: ASN1OptionalEncodingMeta(second_meta_present, first_meta);
	meaning: optional_meaning(meaning_present, meaning_length);
} &let {
	access_present: bool = first_meta.tag == 0xa3;
	second_meta_present: bool = access_present && $context.flow.proc_mms_remaining_check(length, first_meta);
	meaning_present: bool = access_present? second_meta_present && second_meta.data.tag==0xa4 : first_meta.tag==0xa4;
	meaning_length: uint64 = access_present? second_meta.data.length: first_meta.length;
};

type mms_confirmed_res_get_named_var_list_attr_record(length: uint64) = record {
	mms_deletable: ASN1Encoding; #0x80
	
	# The order was off where mms_deletable was stored after list_of_variables. Thus using &requires to force re-order.
	list_of_variables_meta: ASN1EncodingMeta &requires(store_mms_deletable); #0xa1.
	list_of_variables: mms_list_of_variables_items[] &length=list_of_variables_meta.length; # changed from mms_list_of_variables

	# replaced with optionals as presence of accessControlList is optional including the meta.
	#access_control_list_meta: ASN1EncodingMeta;
	#access_control_list	: optional_access_control_list(access_control_list_present, access_control_list_meta.length);
	#next_meta	: ASN1OptionalEncodingMeta(access_control_list_present, access_control_list_meta);
	
	optionals: case access_control_list_present of{
		true 	-> data: mms_access_control_list;
		false	-> none: empty;
	};
	
} &let {
	#access_control_list_present: bool = access_control_list_meta.tag==0xa2;
	
	store_mms_deletable: bool = $context.flow.proc_mms_confirmed_res_get_named_var_list_attr_record(mms_deletable);
	access_control_list_present: bool = (length - $context.flow.get_ASN1Encoding_bytes(mms_deletable.meta) - $context.flow.get_ASN1Encoding_bytes(list_of_variables_meta)) > 0;
};

# TODO: incomplete
type mms_access_control_list = record {
	access_control_list_meta: ASN1EncodingMeta;
	access_control_list: optional_access_control_list(true, access_control_list_meta.length);
}

# Varies from protocol definition as it looks to be ASN1Encoding rather than uint32 or uint8.
type mms_confirmed_res_delete_named_var_list_record = record {	
	number_matched_meta: ASN1EncodingMeta; #uint32 in protocol but seems to be ASN1Encoded and 3 bytes
	number_matched: uint8;				   #TODO: may not always be single byte.
	number_deleted_meta: ASN1EncodingMeta;
	number_deleted: uint8;
};

# TODO: Implementation for readJournal service is incomplete
type mms_confirmed_res_read_journal_record =record {
	list_of_entry_meta: ASN1EncodingMeta;
	list_of_entry: mms_journal_entry;
	more_follows: bytestring &restofdata;
};

type mms_confirmed_res_file_open_record = record {
	frsm_id: ASN1Encoding; 
	file_attr_meta: ASN1EncodingMeta;
	file_attr: mms_file_attributes(file_attr_meta.length);
};

type mms_confirmed_res_file_read_record = record {
	file_data: ASN1Encoding;
	more_follows: bytestring &restofdata; #Boolean
};

type mms_confirmed_res_file_directory_record = record {
	list_of_dir_entry_meta: ASN1EncodingMeta; #0xa0
	seq_meta: ASN1EncodingMeta; #0x30
	list_of_dir_entry: mms_directory_entry[] &length=seq_meta.length;
	more_follows: bytestring &restofdata; #Boolean
};

type optional_list_abs_syntax = record {
	meta: ASN1EncodingMeta;
	list: ASN1Encoding[];
};

type optional_variable_access_spec(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: mms_variable_access_spec_meta &length=length;
	false 	-> none: empty;
};

type optional_address(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: mms_address &length=length;
	false 	-> none: empty;
};

type optional_access_control_list(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: mms_identifier &length=length;
	false	-> none: empty;
};


type optional_meaning(is_present: bool, length: uint64) = case is_present of {
	true 	-> data: mms_object_name &length=length;
	false 	-> none: empty;
};

#==================  MMS SERVICES ===================== 

type mms_status_response(length: uint64) = record {
	vmd_log_status_meta: ASN1EncodingMeta;
	vmd_log_status: uint8;
	vmd_phy_status_meta: ASN1EncodingMeta;
	vmd_phy_status: uint8;
	optional: case local_detail_present of {
		true	-> data: ASN1Encoding; # bitstring
		false	-> none: empty;
	};
} &let {
	r1: uint64 = $context.flow.proc_mms_remaining_length(length, vmd_log_status_meta);
	r2: uint64 = $context.flow.proc_mms_remaining_length(r1, vmd_phy_status_meta);
	local_detail_present = r2 > 0;
};

type mms_variable_access_spec_meta = record {
	meta: ASN1EncodingMeta;
	body: mms_variable_access_spec(meta.tag, meta.length);
} &let {
	proc: bool = $context.flow.proc_mms_variable_access_spec_meta(this);
}

type mms_variable_access_spec(tag: uint8, length: uint64) = case tag of {
	0xa0 	-> a: mms_list_of_variables_items[];
	0xa1	-> b: mms_object_name;
	default	-> unknown: bytestring &restofdata;
} &let {
	proc: bool = $context.flow.proc_mms_variable_access_specification(this);
};

type mms_list_of_variables_items = record {
	meta: ASN1EncodingMeta; #0x30
	body: mms_list_of_variables;
} &let {
	proc: bool = $context.flow.proc_mms_list_of_variables_items(this); #prints asn1 header only
}

type mms_list_of_variables = record {
	# variable spec is called by other services and thus cannot be combined here
	body: mms_variable_specification; 
};

type mms_variable_specification = record {
	body: ASN1Encoding;
}&let{
	proc: bool = $context.flow.proc_mms_variable_specification(this);
};

type mms_journal_entry = record {
	entry_id: ASN1Encoding;
	orig_app_meta: ASN1EncodingMeta;
	orig_app: bytestring &length=orig_app_meta.length; #ApplicationReference
	entry_content_meta: ASN1EncodingMeta;
	entry_content: mms_entry_content(entry_content_meta.length);
};

#======================================================================================= TODO
type mms_entry_content(length: uint64) = record {
	occurence_time: ASN1Encoding;
	meta: ASN1EncodingMeta;
	entry_form: case meta.tag of {
		0xa2	-> data: mms_entry_form_data(entry_form_length);
		0xa3	-> annotation: bytestring &restofdata;
		default	-> unknown: bytestring &restofdata;
	} &requires(entry_form_length);
} &let {
	entry_form_length: uint64 = $context.flow.proc_mms_remaining_length(length, occurence_time.meta);
};

type mms_entry_form_data(length: uint64) = record {
	meta: ASN1EncodingMeta;
	event: optional_entry_content_data_event(event_present);
	next_meta: ASN1OptionalEncodingMeta(remaining, meta);
	list_of_var: optional_journal_var(journal_var_present);
} &let {
	event_present: bool =  meta.tag == 0xa0;
	remaining: uint64 = event_present && $context.flow.proc_mms_remaining_length(length, meta);
	journal_var_present: bool = event_present? remaining && next_meta.data.tag == 0xa1 : meta.tag == 0xa1;
};

type optional_entry_content_data_event(is_present: bool)= case is_present of {
	true	-> data: ASN1Encoding[2];
	false	-> none: empty;
};

type optional_journal_var(is_present: bool) = case is_present of {
	true	-> data: bytestring &restofdata;
	false 	-> none: empty;
};

#======================================================================================= TODO

type mms_directory_entry = record {
	meta: ASN1EncodingMeta; #0x30
	body: mms_directory_entry_items &length=meta.length;
};

type mms_directory_entry_items = record {
	file_name_meta: ASN1EncodingMeta; #0xa0
	file_name: ASN1Encoding; #0x19
	file_attr_meta: ASN1EncodingMeta; #0xa1
	file_attr: mms_file_attributes(file_attr_meta.length);
}

type mms_file_attributes(length: uint64) = record {
	size_of_file: ASN1Encoding;
	last_modified: bytestring &restofdata; #GeneralizedTime, OPTIONAL
};

# ObjectName is a choice structure with options of vmd-specific, domain-specific or aa-specific.
type mms_object_name = record {
	body: ASN1Encoding;
} &let {
	proc: bool = $context.flow.proc_mms_object_name(this);
};

type mms_object_class = record {
	meta: ASN1EncodingMeta;
	body: case meta.tag of {
		0x80	-> a: uint8; #basicObjectClass
		0x81	-> b: uint8; #csObjectclass
	};
}&let{
	proc: bool = $context.flow.proc_mms_object_class(this);
};

type mms_object_scope = record {
	meta: ASN1EncodingMeta;
	body: case meta.tag of {
		0x80 	-> a: empty; #vmdSpecific
		0x81	-> b: bytestring &restofdata; #domainSpecific
		0x82 	-> c: empty; #aaSpecific
		default	-> unknown: bytestring &restofdata;
	};
} &let {
	proc: bool = $context.flow.proc_mms_object_scope(this);
};

type mms_list_of_data = record {
	body: ASN1Encoding[];
} &let {
	proc: bool = $context.flow.proc_mms_list_of_data(this);
}

type mms_data_access_error = record {
	body: uint8;
} &let {
	proc: bool = $context.flow.proc_mms_data_access_error(this);
};

type mms_type_description = record {
	body : ASN1Encoding;
} &let {
	proc: bool = $context.flow.proc_mms_type_description(this);
};

type mms_address = record {
	body: ASN1Encoding;
}&let {
	proc: bool = $context.flow.proc_mms_address(this);
};

type mms_identifier = record {
	body: ASN1Encoding;
} &let {
	proc: bool = $context.flow.proc_mms_identifier(this);
};