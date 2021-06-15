%extern{
#include <bitset>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

//#define DEBUG

#ifdef DEBUG
	#define DEBUG_COUT(str) do { std::cout << str << std::endl; } while( false )
#else
	#define DEBUG_COUT(str) do { } while ( false )
#endif
#ifdef DEBUG
	#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
	#define DEBUG_PRINT(...)
#endif
%}

refine flow MMS_Flow += {
	%member{
		// A bytestring vector is used for intermediate storage of MMS data that spans multiple packets. A flowbuffer assists with reassembly of the packets.
		std::vector<bytestring> v_bytestring;
		std::unique_ptr<FlowBuffer> fb = NULL;
		
		// Flags to determine when to reassemble packet, if needed.
		bool in_fragment = false;
		bool eot_bit = true;

		// A map (invoke id, domain/item id pair) and a data vector to store contents of packet currently being parsed
		std::unordered_map<int, string> domain_item_id_map;
		std::unordered_map<int, string>::iterator domain_item_id_map_iterator;
		std::vector<pair<string, unsigned>> current_pdu_data_pair_vector;
		
		// Data from current packet
		string concatenated_domain_item_id;
		bool is_request;
		int invoke_id = -1;
		int service = -1;
		
		// Check endianness of system
		int n = 1;
		bool is_little_endian = *(char *)&n == 1;

	%}
	
	function proc_tpkt(msg: tpkt): bool
	%{	
		DEBUG_PRINT("\nTPKT: version 0x%x reserved 0x%x length 0x%x => %d\n", ${msg.version}, ${msg.reserved}, ${msg.length}, ${msg.length});		
		return true;
	%}

	function update_is_request(is_orig: bool): bool
	%{
		is_request = is_orig;
		return is_request;
	%}

	function proc_cotp_get_in_fragment(): bool
	%{
		return in_fragment;
	%}

	function proc_cotp_reassembled(): bytestring
	%{
		//FlowBuffer is used to concat bytestring
		fb = std::unique_ptr<FlowBuffer>(new FlowBuffer());
		fb->NewFrame(0, false);
		
		for(bytestring& b: v_bytestring)
			fb->BufferData(b.begin(), b.end());
	
		bytestring b(fb->begin(), fb->end());
		DEBUG_PRINT("Reassembled length is %d\n", b.length());

		//buffer can be cleared
		proc_cotp_clear_buffer();
		
		return b;
	%}

	function proc_cotp_clear_buffer(): bool
	%{	
		//clear flags/data at the last fragment after packet reassembly
		in_fragment = false;
		if (fb!=NULL) fb->DiscardData();
		fb = NULL;
		
		for(auto& bs: v_bytestring)
		{
			bs.free();
		}
		v_bytestring.clear();
		
		return true;
	%}

	function proc_cotp_set_eot_bit(msg: cotp): bool
	%{
		//Set eot_bit if it is a data packet
		if(${msg.body[0]}==TPDU_DT){
			eot_bit = (${msg.body[1]} & 0x80);
			DEBUG_PRINT("COTP EOT bit: %d\n", eot_bit);
		}
		
		return eot_bit;
	%}
			
	function proc_cotp(msg: cotp): bool
	%{
		DEBUG_PRINT("COTP: len %d body ", ${msg.len});
		for(int i=0; i<${msg.len}; i++) DEBUG_PRINT("0x%x ", ${msg.body[i]});
		DEBUG_PRINT("\n");
		return true;
	%}
	
	function proc_session(msg: session): bool
	%{
		switch(${msg.spdu_type})
		{
			case SPDU_CONNECT:
				DEBUG_PRINT("SPDU_CONNECT: type %d len %d\n", ${msg.spdu_type}, ${msg.len});
				break;
			case SPDU_ACCEPT:
				DEBUG_PRINT("SPDU_ACCEPT: type %d len %d\n", ${msg.spdu_type}, ${msg.len});
				break;
			case SPDU_DATA:
				DEBUG_PRINT("SPDU_DATA: type %d len %d\n", ${msg.spdu_type}, ${msg.len});
				break;
			default:
				DEBUG_PRINT("Unknown SPDU: type %d len %d\n", ${msg.spdu_type}, ${msg.len});
				break;
		}
		return true;
	%}
	
	function proc_presentation(msg: presentation): bool
	%{
		switch(${msg.meta.tag})
		{
			case PRES_CONNECT:
				DEBUG_PRINT("PRES_CONNECT: tag 0x%x len 0x%x long_len 0x%x length 0x%lx => %lu\n", ${msg.meta.tag}, ${msg.meta.len}, ${msg.meta.long_len}, ${msg.meta.length}, ${msg.meta.length});
				break;
			case PRES_DATA:
				DEBUG_PRINT("PRES_DATA: tag 0x%x len 0x%x long_len 0x%x length 0x%lx => %lu\n", ${msg.meta.tag}, ${msg.meta.len}, ${msg.meta.long_len}, ${msg.meta.length}, ${msg.meta.length});
				break;
			default:
				DEBUG_PRINT("Unknown PRES: tag 0x%x\n", ${msg.meta.tag});
				break;
		}
		
		return true;
	%}

	function proc_presentation_data_record(msg: presentation_data_record): bool
	%{	
		print_asn1_header("PRES: pdv_meta", ${msg.pdv_meta});
		return true;
	%}
	
	function proc_store_fragment(fragment: bytestring): bool
	%{	
		// First fragment of a long packet
		if(fragment.length()>0)
		{
			bytestring frag(fragment.begin(), fragment.end()); //note: don't use assignment
			v_bytestring.emplace_back(frag);
			DEBUG_PRINT("storing fragment with length %d\n", frag.length());
		}		
		
		return true;
	%}

	function proc_presentation_set_in_fragment(): bool
	%{		
		// First fragment of a long packet
		in_fragment = !in_fragment && !eot_bit;
		return in_fragment;
	%}

	# ========================= MMS =========================

	function proc_mms(msg: mms): bool
	%{
		DEBUG_PRINT("MMS: ");
		switch(${msg.meta.tag})
		{
			case MMS_CONFIRMED_REQ_PDU:
				DEBUG_PRINT("MMS_CONFIRMED_REQ_PDU");
				break;
			case MMS_CONFIRMED_RES_PDU:
				DEBUG_PRINT("MMS_CONFIRMED_RES_PDU");
				break;
			case MMS_INITIATE_REQ_PDU:
				DEBUG_PRINT("MMS_INITIATE_REQ_PDU");
				break;
			case MMS_INITIATE_RES_PDU:
				DEBUG_PRINT("MMS_INITIATE_RES_PDU");
				break;
			case MMS_CONCLUDE_REQ_PDU:
				DEBUG_PRINT("MMS_CONCLUDE_REQ_PDU");
				set_service(BIF_MMS_CONCLUDE_REQ_PDU);
				break;
			case MMS_CONCLUDE_RES_PDU:
				DEBUG_PRINT("MMS_CONCLUDE_RES_PDU");
				set_service(BIF_MMS_CONCLUDE_RES_PDU);
				break;
			case MMS_CANCEL_REQ_PDU:
				DEBUG_PRINT("MMS_CANCEL_REQ_PDU");
				set_service(BIF_MMS_CANCEL_REQ_PDU);
				break;
			case MMS_CANCEL_RES_PDU:
				DEBUG_PRINT("MMS_CANCEL_RES_PDU");
				set_service(BIF_MMS_CANCEL_RES_PDU);
				break;
			default:
				DEBUG_PRINT("Unknown MMS_PDU tag");
				set_service(-1);
				break;		
		}
		DEBUG_PRINT(", tag 0x%x len 0x%x\n", ${msg.meta.tag}, ${msg.meta.len});
		
		return true;
	%}

	# ========================= Event Generation =========================
	
	function generic_event_generator(): bool 
	%{
		VectorVal* vec_data = nullptr;
		VectorVal* vec_datatype = nullptr;
	
		DEBUG_COUT("[MMS PDU TYPE] " << (is_request?"request":"response"));

		// Print the current invoke id
		if(invoke_id != -1)
		{
			DEBUG_COUT("[DATA] invoke id " << invoke_id);
		}

		// If local domain/item id is available, add invoke id--> domain/item id in domain_item_id_map
		if(concatenated_domain_item_id != "")
		{
			this->connection()->upflow()->domain_item_id_map[invoke_id] = concatenated_domain_item_id;
			DEBUG_COUT("[DATA] domain & item id " << concatenated_domain_item_id);
		}
		// If local domain/item id is not available, retrieve from domain_item_id_map
		else if((domain_item_id_map_iterator = this->connection()->upflow()->domain_item_id_map.find(invoke_id)) != this->connection()->upflow()->domain_item_id_map.end())
		{
			concatenated_domain_item_id = domain_item_id_map_iterator->second;
			DEBUG_COUT("[DATA] domain & item id " << concatenated_domain_item_id);
		}
		else 
		{
			DEBUG_COUT("[WARNING] no item id");
		}
		
		//======================Custom Event Generation===================
		//rule_function();

		switch(this->connection()->upflow()->service)
		{
		
			//===========================Request Event Generation===========================
			case BIF_MMS_SERVICE_REQ_GET_NAME_LIST:
			{
				if(::get_name_list_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);
										
					BifEvent::generate_get_name_list_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);												
				}
				break;
			}
			case BIF_MMS_SERVICE_REQ_READ:
			{
				if(::read_request)
				{
					BifEvent::generate_read_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id));
				}
				break;
			}
			case BIF_MMS_SERVICE_REQ_WRITE:
			{
				if(::write_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_write_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}				
				break;
			}
			case BIF_MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR:
			{	
				if(::get_var_access_attr_request)
				{
					BifEvent::generate_get_var_access_attr_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id));
				}
				break;
			}
			case BIF_MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR:
			{
				if(::get_named_var_list_attr_request)
				{
					BifEvent::generate_get_named_var_list_attr_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id));
				}
				break;
			}
			case BIF_MMS_SERVICE_REQ_STATUS:
			{
				if(::status_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_status_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;			
			}
			case BIF_MMS_CONCLUDE_REQ_PDU:
			{
				if(::conclude_request)
				{
					BifEvent::generate_conclude_request(connection()->bro_analyzer(),
												 connection()->bro_analyzer()->Conn());
				}
				break;
			}
			case BIF_MMS_INITIATE_REQ_PDU:
			{
				if(::initiate_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_initiate_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												vec_data,
												vec_datatype);												 
				}
				break;			
			}
			case BIF_MMS_SERVICE_REQ_FILE_DIRECTORY:
			{
				if(::file_directory_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_directory_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}

			case BIF_MMS_SERVICE_REQ_FILE_OPEN:
			{
				if(::file_open_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_open_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}

			case BIF_MMS_SERVICE_REQ_FILE_READ:
			{
				if(::file_read_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_read_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}

			case BIF_MMS_SERVICE_REQ_FILE_CLOSE:
			{
				if(::file_close_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_close_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_REQ_IDENTIFY:
			{
				if(::identify_request)
				{
					BifEvent::generate_identify_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_REQ_FILE_RENAME:
			{
				if(::file_rename_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_rename_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,						
												vec_data,
												vec_datatype);
				}
				break;			
			}
			
			case BIF_MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST:
			{
				if(::define_named_var_list_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_define_named_var_list_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}
				break;			
			}
			
			case BIF_MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST:
			{
				if(::delete_named_var_list_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_delete_named_var_list_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}
				break;				
			}
			
			case BIF_MMS_SERVICE_REQ_OBTAIN_FILE:
			{
				if(::obtain_file_request)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_obtain_file_request(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;				
			}
			
			//===========================Response Event Generation===========================		
			case BIF_MMS_SERVICE_RES_GET_NAME_LIST:
			{
				if(::get_name_list_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);
						
					BifEvent::generate_get_name_list_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_READ:
			{
				if(::read_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);
			
					BifEvent::generate_read_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												//string_to_val(data_string));
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_WRITE:
			{
				if(::write_response)
				{
					BifEvent::generate_write_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id));
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR:
			{
				if(::get_var_access_attr_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_get_var_access_attr_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}			
				break;
			}
			
			case BIF_MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR:
			{
				if(::get_named_var_list_attr_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_get_named_var_list_attr_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												string_to_val(concatenated_domain_item_id),
												vec_data,
												vec_datatype);
				}			
				break;
			}
			
			case BIF_MMS_SERVICE_RES_STATUS:
			{
				if(::status_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_status_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}			
				break;			
			}
			
			case BIF_MMS_CONCLUDE_RES_PDU:
			{
				if(::conclude_response)
				{
					BifEvent::generate_conclude_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn());
				}
				break;
			}
			
			case BIF_MMS_INITIATE_RES_PDU:
			{
				if(::initiate_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_initiate_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												vec_data,
												vec_datatype);
				}
				break;			
			}
			
			case BIF_MMS_SERVICE_RES_FILE_DIRECTORY:
			{
				if(::file_directory_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_directory_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
				
			case BIF_MMS_SERVICE_RES_FILE_OPEN:
			{
				if(::file_open_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_open_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_FILE_READ:
			{
				if(::file_read_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_file_read_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_FILE_CLOSE:
			{
				if(::file_close_response)
				{
					BifEvent::generate_file_close_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_FILE_RENAME:
			{
				if(::file_rename_response)
				{
					BifEvent::generate_file_rename_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id);
				}
				break;			
			}
			
			case BIF_MMS_SERVICE_RES_IDENTIFY:
			{
				if(::identify_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_identify_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST:
			{
				if(::define_named_var_list_response)
				{
					BifEvent::generate_define_named_var_list_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id);
				}
				break;			
			}
			
			case BIF_MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST:
			{
				if(::delete_named_var_list_response)
				{
					vec_data = new VectorVal(internal_type("string_vec")->AsVectorType());
					vec_datatype = new VectorVal(internal_type("index_vec")->AsVectorType());
					update_event_params(vec_data, vec_datatype);

					BifEvent::generate_delete_named_var_list_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id,
												vec_data,
												vec_datatype);
				}
				break;
			}
			
			case BIF_MMS_SERVICE_RES_OBTAIN_FILE:
			{
				if(::obtain_file_response)
				{
					BifEvent::generate_obtain_file_response(connection()->bro_analyzer(),
												connection()->bro_analyzer()->Conn(),
												invoke_id);
				}
				break;
			}
			
			default:
			{
				DEBUG_COUT("No event was generated");		
				break;
			}
		}
		
		// Reset data fields
		is_request = NULL;
		invoke_id = -1;
		concatenated_domain_item_id = "";
		
		this->connection()->upflow()->current_pdu_data_pair_vector.clear();
		set_service(-1);
				
		return true;
	%}

	#============ MMS INITIATE PDU ==========================

	function proc_mms_initiate_req_pdu(msg: mms_initiate_record): bool
	%{
		set_service(BIF_MMS_INITIATE_REQ_PDU);
		
		const char* str_field_1 = ${msg.field_1_present}? "localDetailCalling":"proposedMaxServOutstandingCalling";
		const char* str_field_2 = ${msg.field_1_present}? "proposedMaxServOutstandingCalling": "proposedMaxServOutstandingCalled";
		const char* str_field_3 = ${msg.field_1_present}? "proposedMaxServOutstandingCalled": NULL;

		DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_1, ${msg.field_1.meta.tag}, ${msg.field_1.meta.length}, binary_to_signed_int(${msg.field_1.content}));
		DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_2, ${msg.field_2.meta.tag}, ${msg.field_2.meta.length}, binary_to_signed_int(${msg.field_2.content}));

		store_data(to_string(binary_to_signed_int(${msg.field_1.content})), DATATYPE_INTEGER);
		store_data(to_string(binary_to_signed_int(${msg.field_2.content})), DATATYPE_INTEGER);

		if(str_field_3!=NULL){
			DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_3, ${msg.field_3_data.meta.tag}, ${msg.field_3_data.meta.length}, binary_to_signed_int(${msg.field_3_data.content}));
			store_data(to_string(binary_to_signed_int(${msg.field_3_data.content})), DATATYPE_INTEGER);
		}
		if(${msg.field_4_present}){
			DEBUG_PRINT("MMS proposedDataStructureNestingLevel: tag 0x%x len 0x%lx val %ld\n", ${msg.field_4_meta.tag}, ${msg.field_4_meta.length}, binary_to_signed_int(${msg.field_4_data}));
			store_data(to_string(binary_to_signed_int(${msg.field_4_data})), DATATYPE_INTEGER);
		}			
		
		DEBUG_PRINT("MMS proposed_version_number: tag 0x%x len 0x%lx val %ld\n", ${msg.version_number.meta.tag}, ${msg.version_number.meta.length}, binary_to_signed_int(${msg.version_number.content}));
		store_data(to_string(binary_to_signed_int(${msg.version_number.content})), DATATYPE_INTEGER);

		print_asn1_header("proposed_parameter_cbb", ${msg.parameter_cbb.meta});
		store_data(parse_bit_string(${msg.parameter_cbb}), DATATYPE_BIT_STRING);
		
		print_asn1_header("services_supported_calling", ${msg.services_supported_call.meta});
		store_data(parse_bit_string(${msg.services_supported_call}), DATATYPE_BIT_STRING);

		return true;
	%}
	
	function proc_mms_initiate_additional_params(msg: bytestring): bool
	%{
		// TODO: data is not stored for field values.
		// Expected to have 3 fields: additionalSupportedCalling (bitstring), additionalCBBSupportedCalling (bitstring), privilegeClassIdentityCalling (mms string)
		if(${msg}.length()==0) return true;
		
		ASN1Encoding field;
		const_byteptr start = msg.begin();
		const_byteptr end = msg.end();	
			
		while((end-start)>0)
		{
			field.Parse(start, end);
			print_asn1_header("initiate-additional-parameters", field.meta());
			start+= (get_header_bytes(field.meta()) + field.meta()->length());
		}
				
		return true;
	%}

	function proc_mms_initiate_res_pdu(msg: mms_initiate_record): bool
	%{
		set_service(BIF_MMS_INITIATE_RES_PDU);
		
		const char* str_field_1 = ${msg.field_1_present}? "localDetailCalled":"negotiatedMaxServOutstandingCalling";
		const char* str_field_2 = ${msg.field_1_present}? "negotiatedMaxServOutstandingCalling": "negotiatedMaxServOutstandingCalled";
		const char* str_field_3 = ${msg.field_1_present}? "negotiatedMaxServOutstandingCalled": NULL;

		DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_1, ${msg.field_1.meta.tag}, ${msg.field_1.meta.length}, binary_to_signed_int(${msg.field_1.content}));
		DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_2, ${msg.field_2.meta.tag}, ${msg.field_2.meta.length}, binary_to_signed_int(${msg.field_2.content}));
		
		store_data(to_string(binary_to_signed_int(${msg.field_1.content})), DATATYPE_INTEGER);
		store_data(to_string(binary_to_signed_int(${msg.field_2.content})), DATATYPE_INTEGER);
		
		if(str_field_3!=NULL)
		{
			DEBUG_PRINT("MMS %s: tag 0x%x len 0x%lx val %ld\n", str_field_3, ${msg.field_3_data.meta.tag}, ${msg.field_3_data.meta.length}, binary_to_signed_int(${msg.field_3_data.content}));
			store_data(to_string(binary_to_signed_int(${msg.field_3_data.content})), DATATYPE_INTEGER);
		}
		if(${msg.field_4_present})
		{
			DEBUG_PRINT("MMS negotiatedDataStructureNestingLevel: tag 0x%x len 0x%lx val %ld\n", ${msg.field_4_meta.tag}, ${msg.field_4_meta.length}, binary_to_signed_int(${msg.field_4_data}));
			store_data(to_string(binary_to_signed_int(${msg.field_4_data})), DATATYPE_INTEGER);
		}			
		
		DEBUG_PRINT("MMS negotiatedVersionNumber: tag 0x%x len 0x%lx val %ld\n", ${msg.version_number.meta.tag}, ${msg.version_number.meta.length}, binary_to_signed_int(${msg.version_number.content}));
		store_data(to_string(binary_to_signed_int(${msg.version_number.content})), DATATYPE_INTEGER);

		print_asn1_header("negotiatedParameterCBB", ${msg.parameter_cbb.meta});
		string negotiated_parameter_cbb = parse_bit_string(${msg.parameter_cbb});
		store_data(negotiated_parameter_cbb, DATATYPE_BIT_STRING);
		
		print_asn1_header("services_supported_calling", ${msg.services_supported_call.meta});
		string services_supported_called = parse_bit_string(${msg.services_supported_call});		
		store_data(services_supported_called, DATATYPE_BIT_STRING);

		return true;
	%}
	
	#============ MMS CANCEL PDU ===========================
	# TODO: Unable to test and follow through with event generation without test pcap
	
	function proc_mms_cancel_pdu(msg: mms_cancel_pdu_record): bool
	%{
		// TODO: event is currently not generated
		// store_data(to_string(${msg.body}), DATATYPE_UNSIGNED);
		return true;
	%}

	#============ MMS CONFIRMED REQUEST PDU =================

	function proc_mms_confirmed_req_pdu(msg: mms_confirmed_req_pdu_record): bool
	%{
		DEBUG_PRINT("MMS invoke_ID: tag 0x%x len 0x%x val ", ${msg.invoke_id.meta.tag}, ${msg.invoke_id.meta.len});
		print_bytestring_full(${msg.invoke_id.content});
		invoke_id = binary_to_uint32(${msg.invoke_id.content});
		
		return true;
	%}

	function proc_mms_confirmed_service_request(msg: mms_confirmed_service_request): bool
	%{
		DEBUG_PRINT("MMS service_request: tag 0x%lx len 0x%lx\n", ${msg.tag}, ${msg.length});
		DEBUG_PRINT("MMS confirmed_service_request: ");
		switch(${msg.tag})
		{
			case MMS_SERVICE_REQ_STATUS: 
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_STATUS\n");
				
				string res = ${msg.a}?"true":"false";
				DEBUG_PRINT("Result: val %s\n", res.c_str());
				set_service(BIF_MMS_SERVICE_REQ_STATUS);
				store_data(res, DATATYPE_BOOLEAN);
				break;
			}

			case MMS_SERVICE_REQ_GET_NAME_LIST:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_GET_NAME_LIST\n");
				if (${msg.b.continue_after_present}==1) {
					DEBUG_PRINT("MMS continue_after present\n");
					
				} else {
					DEBUG_PRINT("MMS continue_after not present\n");
				}

				set_service(BIF_MMS_SERVICE_REQ_GET_NAME_LIST);
				break;
			}

			case MMS_SERVICE_REQ_IDENTIFY: 
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_IDENTIFY\n");
				DEBUG_PRINT("NULL: tag 0x%lx len 0x%lx\n", ${msg.tag}, ${msg.length});
				set_service(BIF_MMS_SERVICE_REQ_IDENTIFY);
				break;
			}

			case MMS_SERVICE_REQ_RENAME:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_RENAME\n");
				print_asn1_header("MMS mms_object_class:", ${msg.d.object_class_meta});
				print_asn1_header("MMS mms_current_name:", ${msg.d.current_name_meta});
				print_asn1_header("MMS new_id:", ${msg.d.new_id.meta});
				print_result_to_string("new_id", ${msg.d.new_id.content});
				break;
			}

			case MMS_SERVICE_REQ_READ:
			{	
				DEBUG_PRINT("MMS_SERVICE_REQ_READ\n");
				set_service(BIF_MMS_SERVICE_REQ_READ);
				break;
			}
				
			case MMS_SERVICE_REQ_WRITE:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_WRITE\n");
				set_service(BIF_MMS_SERVICE_REQ_WRITE);
				break;
			}

			case MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR\n");
				set_service(BIF_MMS_SERVICE_REQ_GET_VAR_ACCESS_ATTR);
				break;
			}

			case MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR\n");
				set_service(BIF_MMS_SERVICE_REQ_GET_NAMED_VAR_LIST_ATTR);
				break;
			}

			case MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST\n");
				set_service(BIF_MMS_SERVICE_REQ_DEFINE_NAMED_VAR_LIST);
				break;
			}

			case MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST:
			{	
				DEBUG_PRINT("MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST\n");
				set_service(BIF_MMS_SERVICE_REQ_DELETE_NAMED_VAR_LIST);
				
				if(${msg.length}>0) {
					int scope_of_delete = 0;					
					if(${msg.n.data.scope_present}==1) {
						DEBUG_PRINT("MMS scope_of_delete: %i\n", ${msg.n.data.scope_of_delete.data});
						scope_of_delete = ${msg.n.data.scope_of_delete.data};
					} else {
						DEBUG_PRINT("MMS scope_of_delete: 0\n"); //DEFAULT: 0
						scope_of_delete = 0;
					}
				}		
				break;
			}

			case MMS_SERVICE_REQ_OBTAIN_FILE:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_OBTAIN_FILE\n");
				print_result_to_string("source file", ${msg.au.source_file.content});
				print_result_to_string("destination file", ${msg.au.destination_file.content});
				set_service(BIF_MMS_SERVICE_REQ_OBTAIN_FILE);
				store_data(std_str(${msg.au.source_file.content}), DATATYPE_GRAPHIC_STRING);
				store_data(std_str(${msg.au.destination_file.content}), DATATYPE_GRAPHIC_STRING);
				break;
			}

			// TODO: Implementation for readJournal service is incomplete
			case MMS_SERVICE_REQ_READ_JOURNAL:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_READ_JOURNAL\n");
				
				if (${msg.bn.optionals_present}==1) {

					if (${msg.bn.optional.data.start_present}==1) {
						switch (${msg.bn.optional.data.start.data.meta.tag}) {
							case 0xa0:
								//startingTime
								print_result_to_string("starting_time", ${msg.bn.optional.data.start.data.content});
								break;
							case 0xa1:
								//startingEntry
								print_result_to_string("starting_entry", ${msg.bn.optional.data.start.data.content});
								break;
						}
					}

					if (${msg.bn.optional.data.stop_present}==1) {
						switch (${msg.bn.optional.data.stop.data.meta.tag}) {
							case 0xa0:
								//startingTime
								print_result_to_string("ending_time", ${msg.bn.optional.data.stop.data.content});
								break;
							case 0xa1:
								//startingEntry
								print_result_to_string("number_of_entries", ${msg.bn.optional.data.stop.data.content});
								break;
						}
					}

					if (${msg.bn.optional.data.list_present}==1) {
						for(unsigned int i=0; i<${msg.bn.optional.data.list.data}->size(); i++) {
							DEBUG_PRINT("MMS list_of_variables: var %i\n", i);
							print_result_to_string("list_of_variables", ${msg.bn.optional.data.list.data[i].content});
						}
					}

					if (${msg.bn.optional.data.entry_present}==1) {
						switch (${msg.bn.optional.data.entry.data.meta.tag}) {
							case 0xa0:
								//startingTime
								print_result_to_string("time_specification", ${msg.bn.optional.data.entry.data.content});
								break;
							case 0xa1:
								//startingEntry
								print_result_to_string("entry_specification", ${msg.bn.optional.data.entry.data.content});
								break;
						}
					}
				}
				break;
			}

			case MMS_SERVICE_REQ_FILE_OPEN:
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_OPEN\n");

				print_asn1_header("MMS file_name:", ${msg.bu.file_name_meta});
				print_result_to_string("file_name", ${msg.bu.file_name.content});

				// Uint32
				DEBUG_PRINT("MMS initial_position: val %u\n", binary_to_uint32(${msg.bu.initial_position.content}));

				set_service(BIF_MMS_SERVICE_REQ_FILE_OPEN);
				store_data(std_str(${msg.bu.file_name.content}), DATATYPE_GRAPHIC_STRING);
				store_data(to_string(binary_to_unsigned_int(${msg.bu.initial_position.content})), DATATYPE_UNSIGNED);
				break;

			case MMS_SERVICE_REQ_FILE_READ:
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_READ\n");
				DEBUG_PRINT("MMS frsm_id: val %li\n", binary_to_signed_int(${msg.bv}));
				set_service(BIF_MMS_SERVICE_REQ_FILE_READ);
				store_data(to_string(binary_to_signed_int(${msg.bv})), DATATYPE_INTEGER);
				break;

			case MMS_SERVICE_REQ_FILE_CLOSE:
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_CLOSE\n");
				DEBUG_PRINT("MMS frsm_id: val %li\n", binary_to_signed_int(${msg.bw}));
				set_service(BIF_MMS_SERVICE_REQ_FILE_CLOSE);
				store_data(to_string(binary_to_signed_int(${msg.bw})), DATATYPE_INTEGER);
				break;

			case MMS_SERVICE_REQ_FILE_RENAME:
			{
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_RENAME\n");
				print_result_to_string("current_file", ${msg.bx.current_file.content});
				print_result_to_string("new_file", ${msg.bx.new_file.content});
				set_service(BIF_MMS_SERVICE_REQ_FILE_RENAME);
				store_data(std_str(${msg.bx.current_file.content}), DATATYPE_GRAPHIC_STRING);
				store_data(std_str(${msg.bx.new_file.content}), DATATYPE_GRAPHIC_STRING);
				break;
			}

			case MMS_SERVICE_REQ_FILE_DELETE:
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_DELETE\n");
				print_result_to_string("file_name", ${msg.by.content});
				break;
			
			case MMS_SERVICE_REQ_FILE_DIRECTORY:
			{	
				DEBUG_PRINT("MMS_SERVICE_REQ_FILE_DIRECTORY\n");
				set_service(BIF_MMS_SERVICE_REQ_FILE_DIRECTORY);
				break;
			}	

			default: 
			{
				DEBUG_PRINT("Unknown MMS_SERVICE_REQ\n");
				break;
			}
		}
		return true;
	%}

	function proc_mms_delete_named_var_list(scope_present: bool, scope_of_delete: optional_scope): bool
	%{
		if(scope_present)
		{	
			int a = ${scope_of_delete.data};
			store_data(to_string(${scope_of_delete.data}), DATATYPE_INTEGER);
		}
		
		return true;
	%}

	#============ MMS CONFIRMED RESPONSE PDU =================

	function proc_mms_confirmed_res_pdu(msg: mms_confirmed_res_pdu_record): bool
	%{
		DEBUG_PRINT("MMS invoke_ID: tag 0x%x len 0x%x val ", ${msg.invoke_id.meta.tag}, ${msg.invoke_id.meta.len});
		print_bytestring_full(${msg.invoke_id.content});
		invoke_id = binary_to_uint32(${msg.invoke_id.content});
		
		return true;
	%}

	# Note: Be careful about storing data here, as data in lower levels may get called first and stored first.
	function proc_mms_confirmed_service_response(msg: mms_confirmed_service_response): bool
	%{
		DEBUG_PRINT("MMS service_response: tag 0x%lx len 0x%x\n", ${msg.meta.tag}, ${msg.meta.len});
		DEBUG_PRINT("MMS confirmed_service_response: ");
		
		switch(${msg.meta.tag})
		{
			case MMS_SERVICE_RES_STATUS:
			{
				
				DEBUG_PRINT("MMS_SERVICE_RES_STATUS\n");
				print_asn1_header("MMS vmd_logical_status:", ${msg.a.vmd_log_status_meta});

				DEBUG_PRINT("Result: ");
				switch(${msg.a.vmd_log_status})
				{
					case STATE_CHANGES_ALLOWED:
						DEBUG_PRINT("STATE_CHANGES_ALLOWED\n");
						store_data(to_string(STATE_CHANGES_ALLOWED), DATATYPE_INTEGER);
						break;
					case NO_STATE_CHANGES_ALLOWED:
						DEBUG_PRINT("NO_STATE_CHANGES_ALLOWED\n");
						store_data(to_string(NO_STATE_CHANGES_ALLOWED), DATATYPE_INTEGER);
						break;
					case LIMITED_SERVICES_PERMITTED:
						DEBUG_PRINT("LIMITED_SERVICES_PERMITTED\n");
						store_data(to_string(LIMITED_SERVICES_PERMITTED), DATATYPE_INTEGER);
						break;
					case SUPPORT_SERVICES_ALLOWED:
						DEBUG_PRINT("SUPPORT_SERVICES_ALLOWED\n");
						store_data(to_string(SUPPORT_SERVICES_ALLOWED), DATATYPE_INTEGER);
						break;
					default:
						DEBUG_PRINT("Unknown VMD_LOG_STATUS\n");
						break;
				}
				
				print_asn1_header("MMS vmd_physical_status:", ${msg.a.vmd_phy_status_meta});

				DEBUG_PRINT("Result: ");
				switch(${msg.a.vmd_phy_status})
				{
					case OPERATIONAL:
						DEBUG_PRINT("OPERATIONAL\n");
						store_data(to_string(OPERATIONAL), DATATYPE_INTEGER);
						break;
					case PARTIALLY_OPERATIONAL:
						DEBUG_PRINT("PARTIALLY_OPERATIONAL\n");
						store_data(to_string(PARTIALLY_OPERATIONAL), DATATYPE_INTEGER);
						break;
					case INOPERABLE:
						DEBUG_PRINT("INOPERABLE\n");
						store_data(to_string(INOPERABLE), DATATYPE_INTEGER);
						break;
					case NEEDS_COMMISSIONING:
						DEBUG_PRINT("NEEDS_COMMISSIONING\n");
						store_data(to_string(NEEDS_COMMISSIONING), DATATYPE_INTEGER);
						break;
					default:
						DEBUG_PRINT("Unknown VMD_PHY_STATUS\n");
						break;
				}
				
				set_service(BIF_MMS_SERVICE_RES_STATUS);
				
				if(${msg.a.local_detail_present})
				{
					print_asn1_header("MMS local_detail", ${msg.a.data.meta});
					//DEBUG_PRINT("Result: Bit String\n");
					string result = parse_bit_string(${msg.a.data});
					store_data(result, DATATYPE_BIT_STRING);
				}
				
				break;
			}

			case MMS_SERVICE_RES_GET_NAME_LIST: 
			{
				DEBUG_PRINT("MMS_SERVICE_RES_GET_NAME_LIST\n");
				print_asn1_header("MMS list_of_identifiers", ${msg.b.list_of_identifiers_meta});

				if(${msg.b.more_follows}.length()>0) {
					ASN1Encoding *tmp = bytestring_to_asn1(${msg.b.more_follows});
					DEBUG_PRINT("MMS more_follows: val %u\n", binary_to_uint32(${tmp.content}));
					
					set_service(BIF_MMS_SERVICE_RES_GET_NAME_LIST);
					store_data(binary_to_boolean(${tmp.content}), DATATYPE_BOOLEAN); //TODO: untested
					delete tmp;
				}
				break;
			}
		
			case MMS_SERVICE_RES_IDENTIFY:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_IDENTIFY\n");
				set_service(BIF_MMS_SERVICE_RES_IDENTIFY);				
				print_result_to_string("vendor_name", ${msg.c.vendor_name.content});
				print_result_to_string("model_name", ${msg.c.model_name.content});
				print_result_to_string("revision", ${msg.c.revision.content});
				
				store_data(std_str(${msg.c.vendor_name.content}), DATATYPE_VISIBLE_STRING);
				store_data(std_str(${msg.c.model_name.content}), DATATYPE_VISIBLE_STRING);
				store_data(std_str(${msg.c.revision.content}), DATATYPE_VISIBLE_STRING);
				
				if (${msg.c.abs_syntax_present}==1) {
				 	for(unsigned int i=0; i<${msg.c.data.list}->size(); i++) {
						// TODO: Parse object identifier
				 	}
				}
				break;
			}

			case MMS_SERVICE_RES_RENAME:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_RENAME NULL: tag 0x%x len 0x%x\n", ${msg.d.meta.tag}, ${msg.d.meta.len});
				break;
			}
			
			case MMS_SERVICE_RES_READ:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_READ\n");
				if(${msg.e.access_result_tag}==0xa0) DEBUG_PRINT("MMS access_result: failure\n");
				if(${msg.e.access_result_tag}==0xa1) DEBUG_PRINT("MMS access_result: success\n");
				set_service(BIF_MMS_SERVICE_RES_READ);
				break;
			}
			
			case MMS_SERVICE_RES_WRITE:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_WRITE\n");
				switch(${msg.f.meta.tag}) {
					case 0x80:
						print_asn1_header("MMS failure:", ${msg.f.meta});
						break;
					case 0x81:
						print_asn1_header("MMS success:", ${msg.f.meta});
						break;
					default: 
						print_asn1_header("MMS unknown:", ${msg.f.meta});
						break;
				}

				set_service(BIF_MMS_SERVICE_RES_WRITE);
				break;
			}

			case MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR\n");
				set_service(BIF_MMS_SERVICE_RES_GET_VAR_ACCESS_ATTR);
				break;
			}		
			case MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR\n");
				set_service(BIF_MMS_SERVICE_RES_GET_NAMED_VAR_LIST_ATTR);
				break;
			}
			case MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST --> NULL\n");
				set_service(BIF_MMS_SERVICE_RES_DEFINE_NAMED_VAR_LIST);
				break;
			}
			case MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST:
			{	
				DEBUG_PRINT("MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST\n");
				DEBUG_PRINT("MMS number_matched: %i\n", ${msg.n.number_matched});
				DEBUG_PRINT("MMS number_deleted: %i\n", ${msg.n.number_deleted});
				set_service(BIF_MMS_SERVICE_RES_DELETE_NAMED_VAR_LIST);
				store_data(to_string(${msg.n.number_matched}), DATATYPE_UNSIGNED);
				store_data(to_string(${msg.n.number_deleted}), DATATYPE_UNSIGNED);
			}
			break;

			case MMS_SERVICE_RES_OBTAIN_FILE:
				DEBUG_PRINT("MMS_SERVICE_RES_OBTAIN_FILE --> NULL\n");
				set_service(BIF_MMS_SERVICE_RES_OBTAIN_FILE);
				break;
			
			// TODO: Implementation for readJournal service is incomplete
			case MMS_SERVICE_RES_READ_JOURNAL:
			{
				DEBUG_PRINT("MMS_SERVICE_RES_READ_JOURNAL\n");
				print_asn1_header("MMS entry_id meta: ", ${msg.bn.list_of_entry.entry_id.meta});
				print_result_to_string("MMS entry_id", ${msg.bn.list_of_entry.entry_id.content});

				print_result_to_string("occurence_time", ${msg.bn.list_of_entry.entry_content.occurence_time.content});

				switch(${msg.bn.list_of_entry.entry_content.meta.tag}) 
				{
					case 0xa2: /* data */
					{
						// if (${msg.bn.list_of_entry.entry_content.entry_form.data.event_present} == 1) {
						// 	/* TODO */
							
						// 	// parse_object_name(${msg.bn.list_of_entry.entry_content.entry_form.data.event.data[1]});
						// 	// print_result_to_string(${msg.bn.list_of_entry.entry_content.entry_form.data.event.data[2]});
						// }

						// if (${msg.bn.list_of_entry.entry_content.entry_form.data.journal_var_present} == 1) {
						// 	// TODO 
						// }

						break;
					}
					case 0xa3: /* annotation */
						// print_result_to_string("annotation", ${msg.bn.list_of_entry.entry_content.entry_form.annotation});
						break;
					default:
						DEBUG_PRINT("MMS entry_form UNKNOWN\n");
						break;
				}
				break;
			}

			case MMS_SERVICE_RES_FILE_OPEN:
			{	
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_OPEN\n");
				set_service(BIF_MMS_SERVICE_RES_FILE_OPEN);
								
				DEBUG_PRINT("MMS frsm_id: val %li\n", binary_to_signed_int(${msg.bu.frsm_id.content}));
				print_asn1_header("MMS file_attr_meta:", ${msg.bu.file_attr_meta});
				DEBUG_PRINT("Result: size_of_file --> val %u\n", binary_to_uint32(${msg.bu.file_attr.size_of_file.content}));

				store_data(to_string(binary_to_signed_int(${msg.bu.frsm_id.content})), DATATYPE_INTEGER);
				store_data(to_string(binary_to_uint32(${msg.bu.file_attr.size_of_file.content})), DATATYPE_UNSIGNED);
								
				if(${msg.bu.file_attr.last_modified}.length()>0) {
					ASN1Encoding *tmp = bytestring_to_asn1(${msg.bu.file_attr.last_modified});
					print_result_to_string("last_modified", ${tmp.content});
					store_data(std_str(${tmp.content}), DATATYPE_GENERALIZED_TIME);
					delete tmp;
				}
				
				break;
			}	

			case MMS_SERVICE_RES_FILE_READ:
			{	
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_READ\n");
				set_service(BIF_MMS_SERVICE_RES_FILE_READ);

				//print_result_to_string("file_data", ${msg.bv.file_data.content});
				
				DEBUG_COUT("MMS file_data ");
				string result = parse_octet_string(${msg.bv.file_data});
				store_data(result, DATATYPE_OCTET_STRING);
				
				if(${msg.bv.more_follows}.length()>0) {
					ASN1Encoding *tmp = bytestring_to_asn1(${msg.bv.more_follows});
					DEBUG_PRINT("MMS more_follows: val %d\n", binary_to_uint32(${tmp.content}));
					store_data(binary_to_boolean(${tmp.content}), DATATYPE_BOOLEAN);
					delete tmp;
				}
				break;	
			}

			case MMS_SERVICE_RES_FILE_CLOSE:
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_CLOSE --> NULL\n");
				set_service(BIF_MMS_SERVICE_RES_FILE_CLOSE);
				break;	

			case MMS_SERVICE_RES_FILE_RENAME:
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_RENAME --> NULL\n");
				set_service(BIF_MMS_SERVICE_RES_FILE_RENAME);
				break;	

			case MMS_SERVICE_RES_FILE_DELETE:
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_DELETE --> NULL\n");
				break;
			
			case MMS_SERVICE_RES_FILE_DIRECTORY:
			{	
				DEBUG_PRINT("MMS_SERVICE_RES_FILE_DIRECTORY\n");
				set_service(BIF_MMS_SERVICE_RES_FILE_DIRECTORY);
				
				for(unsigned int i=0; i<${msg.bz.list_of_dir_entry}->size(); i++) {
					DEBUG_PRINT("MMS directory_entry: %i\n", i);
					print_result_to_string("file_name", ${msg.bz.list_of_dir_entry[i].body.file_name.content});
					store_data(std_str(${msg.bz.list_of_dir_entry[i].body.file_name.content}), DATATYPE_GRAPHIC_STRING);
					
					DEBUG_PRINT("Result: size_of_file --> val %d\n", binary_to_uint32(${msg.bz.list_of_dir_entry[i].body.file_attr.size_of_file.content}));
					store_data(to_string(binary_to_uint32(${msg.bz.list_of_dir_entry[i].body.file_attr.size_of_file.content})), DATATYPE_UNSIGNED);
					
					if(${msg.bz.list_of_dir_entry[i].body.file_attr.last_modified}.length()>0) {
						ASN1Encoding *tmp = bytestring_to_asn1(${msg.bz.list_of_dir_entry[i].body.file_attr.last_modified});
						print_result_to_string("last_modified", ${tmp.content});
						store_data(std_str(${tmp.content}), DATATYPE_GENERALIZED_TIME);
						delete tmp;
					}
				}
				if(${msg.bz.more_follows}.length()>0) {
					ASN1Encoding *tmp = bytestring_to_asn1(${msg.bz.more_follows});
					DEBUG_PRINT("MMS more_follows: val %d\n", binary_to_uint32(${tmp.content}));
					store_data(binary_to_boolean(${tmp.content}), DATATYPE_BOOLEAN);
					delete tmp;
				}
				break;
			}		
			default:
					DEBUG_PRINT("Unknown MMS_SERVICE_RES: tag 0x%lx len 0x%x\n", ${msg.meta.tag}, ${msg.meta.len});
				break;
			}
		return true;
	%}

	function proc_mms_confirmed_res_get_named_var_list_attr_record(msg: ASN1Encoding): bool
	%{
		DEBUG_PRINT("MMS mms_deletable: tag 0x%x len 0x%x val %u\n", 
		${msg.meta.tag}, ${msg.meta.len}, binary_to_uint32(${msg.content}));
		store_data(binary_to_boolean(${msg.content}), DATATYPE_BOOLEAN);
		
		return true;
	%}
	
	function proc_mms_confirmed_res_get_var_access_attr_record(msg: mms_confirmed_res_get_var_access_attr_record): bool
	%{
		DEBUG_PRINT("MMS mms_deletable: tag 0x%x len 0x%x val %u\n", 
		${msg.mms_deletable.meta.tag}, ${msg.mms_deletable.meta.len}, binary_to_uint32(${msg.mms_deletable.content}));
		store_data(binary_to_boolean(${msg.mms_deletable.content}), DATATYPE_BOOLEAN);
	
		return true;	
	%}

	#=========== MMS CONFIRMED REQUEST SERVICES ==============

	function proc_mms_confirmed_req_read_record(msg: mms_confirmed_req_read_record): bool
	%{
		if(${msg.spec_with_result_present}==1)
		{
			DEBUG_PRINT("MMS spec_with_result: %d\n", ${msg.spec_with_result.data});
		} else {
			DEBUG_PRINT("MMS spec_with_result: 0\n");
		}
		return true;
	%}

	#==================  MMS SERVICES ===================== 

	function proc_mms_variable_access_spec_meta(msg: mms_variable_access_spec_meta): bool
	%{
		print_asn1_header("MMS variable_access_spec_meta:", ${msg.meta});
		return true;
	%}

	function proc_mms_variable_access_specification(msg: mms_variable_access_spec): bool
	%{
		switch(${msg.tag})
		{
			case 0xa0:
				DEBUG_PRINT("MMS list_of_variable_items: ");
				break;
			case 0xa1:
				DEBUG_PRINT("MMS object_name: ");
				break;
		}
		DEBUG_PRINT("tag 0x%x len 0x%lx\n", ${msg.tag}, ${msg.length});
		return true;
	%}
	
	function proc_mms_list_of_variables_items(msg: mms_list_of_variables_items): bool
	%{
		print_asn1_header("MMS list_of_variables:",${msg.meta});
		return true;
	%}

	function proc_mms_variable_specification(msg: mms_variable_specification): bool
	%{
		parse_variable_specification(${msg.body});
		return true;
	%}

	function proc_mms_object_name(msg: mms_object_name): bool
	%{
		parse_object_name(${msg.body});
		return true;
	%}

	function proc_mms_object_class(msg: mms_object_class): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80:
				print_asn1_header("MMS basic_object_class:", ${msg.meta});
				store_data(to_string(${msg.a}), DATATYPE_INTEGER);
				switch(${msg.a})
				{
					case 0:
						DEBUG_PRINT("Result: namedVariable\n");
						break;
					case 1:
						DEBUG_PRINT("Result: scatteredAccess\n");
						break;
					case 2:
						DEBUG_PRINT("Result: namedVariableList\n");
						break;
					case 3:
						DEBUG_PRINT("Result: namedType\n");
						break;
					case 4:
						DEBUG_PRINT("Result: semaphore\n");
						break;
					case 5:
						DEBUG_PRINT("Result: eventCondition\n");
						break;
					case 6:
						DEBUG_PRINT("Result: eventAction\n");
						break;
					case 7:
						DEBUG_PRINT("Result: eventEnrollment\n");
						break;
					case 8:
						DEBUG_PRINT("Result: journal\n");
						break;
					case 9:
						DEBUG_PRINT("Result: domain\n");
						break;
					case 10:
						DEBUG_PRINT("Result: programInvocation\n");
						break;
					case 11:
						DEBUG_PRINT("Result: operatorStation\n");
						break;
					case 12:
						DEBUG_PRINT("Result: dataExchange\n");
						break;
					case 13:
						DEBUG_PRINT("Result: accessControlList\n");
						break;
			}
			break;
			
			case 0x81:
				print_asn1_header("MMS cs_object_class:", ${msg.meta});
				case 0:
					DEBUG_PRINT("Result: eventConditionList\n");
					break;
				case 1:
					DEBUG_PRINT("Result: unitControl\n");
					break;

		}
		return true;
	%}

	function proc_mms_object_scope(msg: mms_object_scope): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80:
				DEBUG_PRINT("MMS vmdSpecific: NULL\n");
				break;
			case 0x81:
			{
				print_result_to_string("domainSpecific", ${msg.b});
				if(concatenated_domain_item_id=="")
				{
					set_request_identifier(std_str(${msg.b}));
				}
				else
				{
					DEBUG_PRINT("[WARNING] Global Domain & Item ID has already been set. It will not be overwritten.\n");
				}
				break;
			}
			case 0x82:
				DEBUG_PRINT("MMS aaSpecific: NULL\n");
				break;
		}
		return true;
	%}
	
	function proc_mms_list_of_data(msg: mms_list_of_data): bool
	%{
		for(unsigned int i=0; i<${msg.body}->size(); i++)
		{
			parse_data(${msg.body[i]});
		}
		return true;
	%}

	function proc_mms_data_access_error(msg: mms_data_access_error): bool
	%{
		DEBUG_PRINT("MMS data_access_error: ");
		switch(${msg.body}) 
		{
			case DATAACCESSERROR_OBJECT_INVALIDATED:
				DEBUG_PRINT("object-invalidated\n");
				break;
			case DATAACCESSERROR_HARDWARE_FAULT:
				DEBUG_PRINT("hardware-fault\n");
				break;
			case DATAACCESSERROR_TEMPORARILY_UNAVAILABLE:
				DEBUG_PRINT("temporarily-unavailable\n");
				break;
			case DATAACCESSERROR_OBJECT_ACCESS_DENIED:
				DEBUG_PRINT("object-access-denied\n");
				break;
			case DATAACCESSERROR_OBJECT_UNDEFINED:
				DEBUG_PRINT("object-undefined\n");
				break;
			case DATAACCESSERROR_INVALID_ADDRESS:
				DEBUG_PRINT("invalid-address\n");
				break;
			case DATAACCESSERROR_TYPE_UNSUPPORTED:
				DEBUG_PRINT("type-unsupported\n");
				break;
			case DATAACCESSERROR_TYPE_INCONSISTENT:
				DEBUG_PRINT("type-inconsistent\n");
				break;
			case DATAACCESSERROR_OBJECT_ATTRIBUTE_INCOSISTENT:
				DEBUG_PRINT("object-attribute-inconsistent\n");
				break;
			case DATAACCESSERROR_OBJECT_ACCESS_UNSUPPORTED:
				DEBUG_PRINT("object-access-unsupported\n");
				break;
			case DATAACCESSERROR_OBJECT_NON_EXISTENT:
				DEBUG_PRINT("object-non-existent\n");
				break;
			case DATAACCESSERROR_OBJECT_VALUE_INVALID:
				DEBUG_PRINT("object-value-invalid\n");
				break;
		}
		return true;
	%}

	function proc_mms_type_description(msg: mms_type_description): bool
	%{
		parse_type_description(${msg.body});
		return true;
	%}

	function proc_mms_address(msg: mms_address): bool
	%{
		parse_address(${msg.body});
		return true;
	%}

	function proc_mms_identifier(msg: mms_identifier): bool
	%{
		DEBUG_PRINT("Result: %s\n", std_str(${msg.body.content}).c_str());
		store_data(std_str(${msg.body.content}), DATATYPE_VISIBLE_STRING);
		return true;
	%}

	function proc_mms_file_directory(msg: mms_file_directory): bool
	%{
		if(${msg.file_spec_present} == 1) {
			print_result_to_string("file_spec", ${msg.file_spec.data.content});
			store_data(std_str(${msg.file_spec.data.content}), DATATYPE_GRAPHIC_STRING);
		} else {
			DEBUG_PRINT("Result: file_spec --> not present\n");
		}
		if(${msg.continue_after_present == 1}) {
			print_result_to_string("file_spec", ${msg.continue_after.data.content});
			store_data(std_str(${msg.continue_after.data.content}), DATATYPE_GRAPHIC_STRING);
		} else {
			DEBUG_PRINT("Result: continue_after --> not present\n");
		}
		return true;
	%}

	function proc_mms_confirmed_res_get_name_list_record(msg: mms_confirmed_res_get_name_list_record): bool
	%{
		for(unsigned int i=0; i<${msg.list_of_identifiers}->size(); i++) {
			string result = std_str(${msg.list_of_identifiers[i].content});
			DEBUG_PRINT("MMS list_of_identifiers: tag 0x%x len 0x%x val %s\n", ${msg.list_of_identifiers[i].meta.tag}, 
			${msg.list_of_identifiers[i].meta.len}, 
			result.c_str());
			
			store_data(result, DATATYPE_VISIBLE_STRING);
		}
		
		return true;
	%}

	#============================= PARSERS ============================

	# The interpretation of dataypes of parse_type_description data varies from regular services such as read and write
	function parse_type_description(msg: ASN1Encoding): bool
	%{ 
		switch(${msg.meta.tag})
		{
			case DATATYPE_ARRAY:
			{
				print_asn1_header("Result: Array", ${msg.meta});
				//the struct contents would contain the full bytestring for further processing
				const_byteptr moving_target_begin = ${msg.content}.begin();
				const_byteptr target_end = ${msg.content}.end();
			
				while(moving_target_begin!=target_end)
				{
					//read the data
					ASN1Encoding tmp;
					tmp.Parse(moving_target_begin, target_end);
					int data_length = tmp.meta()->length();
					int header_length = get_header_bytes(tmp.meta());
					
					parse_type_description_array(&tmp);
					moving_target_begin += (data_length + header_length);
				}
				break;
			}
			case DATATYPE_STRUCTURE:
			{
				/* STRUCTURE - SEQUENCE */

				print_asn1_header("Result: Structure", ${msg.meta}); 

				const_byteptr moving_target_begin = ${msg.content}.begin(); 
				const_byteptr target_end = ${msg.content}.end();

				ASN1Encoding * tmp = new ASN1Encoding();
				tmp->Parse(moving_target_begin, target_end);
				int data_length = ${tmp.meta.length};
				int header_length = get_header_bytes(${tmp.meta});

				if (${tmp.meta.tag}==0x80) {
					DEBUG_PRINT("Result: Packed\n");
					DEBUG_PRINT("Result: %u\n", binary_to_uint32(${tmp.content}));
					
					moving_target_begin += (data_length + header_length);
					
					ASN1Encoding components;
					components.Parse(moving_target_begin, target_end);
					int data_length = components.meta()->length();
					int header_length = get_header_bytes(components.meta());

					parse_type_description_structure(&components);					
					
				} else {
					/* tmp -> tag = 0xa1 components */
					parse_type_description_structure(tmp);
				}
				
				delete tmp;
				
				break;
			}
			case DATATYPE_BOOLEAN:
				DEBUG_PRINT("Result: Boolean NULL\n");
				store_data("", DATATYPE_BOOLEAN);
				break;
			case DATATYPE_BIT_STRING: //represented as int32
			{	
				// The msg contents represents an int32 specifying the max length of the component	
				int64 res = binary_to_signed_int(${msg.content});

				DEBUG_PRINT("Result: Bit String --> %ld\n", res);
				print_bytestring_full(${msg.content});
				store_data(to_string(res), DATATYPE_INTEGER);								
				break;
			}	
			case DATATYPE_INTEGER: // represented as unsigned8
			{
				int64 res = binary_to_signed_int(${msg.content});
				DEBUG_PRINT("Result: Integer --> %ld\n", res);
				store_data(to_string(res), DATATYPE_UNSIGNED);
				break;
			}
			case DATATYPE_UNSIGNED: //represented as unsigned8
			{
				uint32 res = binary_to_uint32(${msg.content});
				DEBUG_PRINT("Result: Unsigned Integer tag 0x%x len 0x%x val %u\n", ${msg.meta.tag}, ${msg.meta.len}, res);
				store_data(to_string(res), DATATYPE_UNSIGNED);
				break;
			}
			case DATATYPE_FLOATING_POINT: /*TODO: sequence of 2 unsigned8*/
				DEBUG_PRINT("Result: Floating Point --> format-width and exponent-width\n");
				print_bytestring_full(${msg.content});
				break;
			case DATATYPE_OCTET_STRING: //represented as int32
			{
				int64 res = binary_to_signed_int(${msg.content});
				DEBUG_PRINT("Result: Octet String --> %ld\n", res);
				store_data(to_string(res), DATATYPE_OCTET_STRING);
				break;
			}
			case DATATYPE_VISIBLE_STRING: //represented as int32
			{
				int64 res = binary_to_signed_int(${msg.content});
				DEBUG_PRINT("Result: Visible String --> %ld\n", res);
				store_data(to_string(res), DATATYPE_VISIBLE_STRING);
				break;
			}
			case DATATYPE_GENERALIZED_TIME:
				DEBUG_PRINT("Result: Generalized Time NULL\n");
				store_data("", DATATYPE_GENERALIZED_TIME);
				break;
			case DATATYPE_BINARY_TIME: //represented as boolean
				DEBUG_PRINT("Result: Binary Time --> %s\n", binary_to_boolean(${msg.content}).c_str());
				break;
			case DATATYPE_BCD: //represented as unsigned8
				DEBUG_PRINT("Result: BCD %lu\n", binary_to_unsigned_int(${msg.content}));
				break;
			case DATATYPE_OBJID:
				DEBUG_PRINT("Result: OBJID NULL\n");
				break;
			case DATATYPE_MMS_STRING: //represented as int32
				DEBUG_PRINT("Result: MMS String--> %ld\n", binary_to_signed_int(${msg.content}));
				break;
			default:
				DEBUG_PRINT("Result: Unknown TYPE_DESCRIPTION\n");
				break;
		}
		return true;
	%}

	function parse_type_description_array(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag}) 
		{
			case 0x80:
				DEBUG_PRINT("Result: Packed %d\n", binary_to_uint32(${msg.content}));
				break;
			case 0xa1:
				DEBUG_PRINT("Result: Number Of Elements %u\n", binary_to_uint32(${msg.content}));
				break;
			case 0xa2:
			{
				ASN1Encoding *tmp = bytestring_to_asn1(${msg.content});
				parse_type_specification(${tmp}); /* CHOICE */
				delete tmp;
				break;
			}
		}
		return true;
	%}

	function parse_type_specification(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80: /* typeName */
			{
				ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
				parse_object_name(${tmp});
				delete tmp;
				break;
			}
			default: /* typeDescription */
				parse_type_description(${msg});
				break;
		}
		return true;
	%}

	function parse_type_description_structure(msg: ASN1Encoding): bool
	%{
		const_byteptr moving_target_begin = ${msg.content}.begin(); 
		const_byteptr target_end = ${msg.content}.end();
		
		std::vector<bytestring> component_seq; // vector of datastring<unsigned char>
		int seq_count = 0;
		
		while(moving_target_begin!=target_end)
		{
			ASN1Encoding seq; /* starts w/ 0x30 */
			seq.Parse(moving_target_begin, target_end);
			int data_length = seq.meta()->length();
			int header_length = get_header_bytes(seq.meta());

			//making a copy of content instead of using ref to manage memory of ASN1Encoding object
			component_seq.emplace_back(bytestring(seq.content().begin(),seq.content().end()));
			seq_count++;

			moving_target_begin += (data_length + header_length);
		}

		for (auto & element : component_seq) {
			parse_component_items(element);
			element.free();
		}

		return true;
	%}

	function parse_component_items(msg: bytestring): bool
	%{
		const_byteptr moving_target_begin = ${msg}.begin(); 
		const_byteptr target_end = ${msg}.end();
		
		while(moving_target_begin!=target_end)
		{
			ASN1Encoding * tmp = new ASN1Encoding();
			tmp->Parse(moving_target_begin, target_end);
			int data_length = ${tmp.meta.length};
			int header_length = get_header_bytes(${tmp.meta});

			switch(${tmp.meta.tag})
			{
				case 0x80:
					print_asn1_header("MMS component_name meta:", ${tmp.meta});
					print_result_to_string("component_name", ${tmp.content});
					store_data(std_str(${tmp.content}), DATATYPE_VISIBLE_STRING);
					break;
				case 0xa1:
				{	
					int index = rand() % 100;
					DEBUG_PRINT("MMS Component Type\n");
					ASN1Encoding * tmp2 = bytestring_to_asn1(${tmp.content});
					parse_type_description(${tmp2});
					delete tmp2;
					break;
				}
			}
			moving_target_begin += (data_length + header_length);
			delete tmp;
		}
		return true;
	%}

	function parse_data(msg: ASN1Encoding): bool
	%{
		print_asn1_header("meta: ", ${msg.meta});
		switch(${msg.meta.tag})
		{
			case DATATYPE_ARRAY:
			{
				const_byteptr moving_target_begin = ${msg.content}.begin();
				const_byteptr target_end = ${msg.content}.end();
			
				while(moving_target_begin!=target_end)
				{
					ASN1Encoding tmp;
					tmp.Parse(moving_target_begin, target_end);
					int data_length = tmp.meta()->length();
					int header_length = get_header_bytes(tmp.meta());
					parse_data(&tmp);
					moving_target_begin += (data_length + header_length);
				}
				break;
			}
			case DATATYPE_STRUCTURE:
			{	
				DEBUG_PRINT("Result: Structure\n");
				//the struct contents would contain the full bytestring for further processing
				const_byteptr moving_target_begin = ${msg.content}.begin();
				const_byteptr target_end = ${msg.content}.end();
				
				while(moving_target_begin!=target_end)
				{
					ASN1Encoding tmp;
					tmp.Parse(moving_target_begin, target_end);
					int data_length = tmp.meta()->length();
					int header_length = get_header_bytes(tmp.meta());
					parse_data(&tmp);
					moving_target_begin += (data_length + header_length);					
				}
				break;
			}	
			case DATATYPE_BOOLEAN:
			{
				string result = binary_to_boolean(${msg.content});
				DEBUG_PRINT("Result: Boolean --> %s\n", result.c_str());
				store_data(result, DATATYPE_BOOLEAN);
				break;
			}
			case DATATYPE_BIT_STRING:
			{
				//DEBUG_PRINT("Result: Bit String\n");
				string result = parse_bit_string(${msg});
				store_data(result, DATATYPE_BIT_STRING);
				break;
			}	
			case DATATYPE_INTEGER:
			{
				DEBUG_PRINT("Result: Integer --> %ld\n", binary_to_signed_int(${msg.content}));
				string result = to_string(binary_to_signed_int(${msg.content}));
				DEBUG_COUT("Value: " << result);
				store_data(result, DATATYPE_INTEGER);
				break;
			}
			case DATATYPE_UNSIGNED:
			{
				DEBUG_PRINT("Result: Unsigned Integer --> %lu\n", binary_to_unsigned_int(${msg.content}));
				string result = to_string(binary_to_unsigned_int(${msg.content}));
				DEBUG_COUT("Value: " << result);
				store_data(result, DATATYPE_UNSIGNED);
				break;
			}	
			case DATATYPE_FLOATING_POINT:
			{
				// There are two valid formats for floating point representation; with 4 bytes or 5 bytes.
				// When it is 5 bytes, the first byte represents the length of the exponent in bits (8).
				// The remaining bytes follow IEEE 754 single precision format.
				// Reference: https://iec61850.tissue-db.com/tissue/817
				DEBUG_PRINT("Result: Floating Point\n");
				int offset = ${msg.content}.length()>4;
				bytestring b(${msg.content}.begin()+offset, ${msg.content}.end());
				print_bytestring_full(b);
				float y = 0.0;
				if(this->connection()->upflow()->is_little_endian){
					const char * c = reinterpret_cast<const char*>(b.data());
					char c2[4];
					c2[3] = c[0];
					c2[2] = c[1];
					c2[1] = c[2];
					c2[0] = c[3];
					memcpy(&y, c2, 4);
				} else {
					memcpy(&y, b.begin(), b.length());
				}
				
				string result = to_string(y);
				store_data(result, DATATYPE_FLOATING_POINT);
				DEBUG_COUT("Value: " << result);
				b.free();
				
				break;
			}
			case DATATYPE_OCTET_STRING:
			{
				//DEBUG_PRINT("Result: Octet String\n");
				string result = parse_octet_string(${msg});
				store_data(result, DATATYPE_OCTET_STRING);
				break;
			}
			case DATATYPE_VISIBLE_STRING:
			{
				DEBUG_PRINT("Result: Visible String --> %s\n", std_str(${msg.content}).c_str());
				string result = std_str(${msg.content});
				store_data(result, DATATYPE_VISIBLE_STRING);
				break;
			}
			case DATATYPE_UTC_TIME:
			{
				DEBUG_PRINT("Result: UTC Time\n");
				stringstream string_builder;
				string_builder << "";
				bytestring const& bs = msg->content();
				int64 rval = 0;
				for(unsigned i = 0; i < 4; i++){
					uint64 byte = bs[i];
					rval |= byte << (8 * (bs.length() - (i + 1) - 4));
				}
				std::time_t time = rval;
				string_builder << std::put_time(std::gmtime(&time), "%c %Z");
				string result = string_builder.str();
				
				store_data(result, DATATYPE_UTC_TIME);
				DEBUG_COUT("Value: " << result);
				break;
			}
			
			//======================================================================================================================================
			//TODO: these datatypes are not stored in data vector as they have not been tested.
			case DATATYPE_BINARY_TIME: //Octet string format. TODO: parse accordingly.
				DEBUG_PRINT("Result: Binary Time tag 0x%x len 0x%x\n", ${msg.meta.tag}, ${msg.meta.len});
				break;
			case DATATYPE_BCD: //Integer, not negative
				DEBUG_PRINT("Result: BCD %lu\n", binary_to_unsigned_int(${msg.content}));
				break;
			case DATATYPE_OBJID:
				DEBUG_PRINT("Result: OBJID NULL tag 0x%x len 0x%x\n", ${msg.meta.tag}, ${msg.meta.len});
				break;
			//=======================================================================================================================================
				
			case DATATYPE_MMS_STRING: //Visible String
			{	DEBUG_PRINT("Result: MMS String  tag 0x%x len 0x%x val %s\n", ${msg.meta.tag}, ${msg.meta.len}, std_str(${msg.content}).c_str());
				string result = std_str(${msg.content});
				store_data(result, DATATYPE_MMS_STRING);				
				break;
			}
			default:
				DEBUG_PRINT("Result: Unknown DATA\n");
				break;
		}
		return true;
	%}

	function parse_alternate_access(msg: ASN1Encoding): bool
	%{
		ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
		switch(${msg.meta.tag})
		{
			case 0xa5:
			{
				// named [5]
				switch(${tmp.meta.tag})
				{
					case 0x80:
					{ // componentName [0]
						print_asn1_header("MMS component_name meta:", ${msg.meta});
						print_result_to_string("component_name", ${msg.content});
						break;
					}
					default:
					{ // access [no tag]
						parse_alternate_access_selection(${tmp});
						break;
					}
				}
				break;
			}
			default:
			{   //unnamed [no tag]
				parse_alternate_access_selection(${msg});
				break;
			}
		}
		
		delete tmp;
		return true;
	%}

	function parse_alternate_access_selection(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0xa0:
			{	//selectAlternateAccess [0]
				ASN1Encoding *tmp = bytestring_to_asn1(${msg.content});
				parse_select_alternate_access(${tmp});
				delete tmp;
				break;
			}
			default:
			{
				ASN1Encoding *pass_msg = msg;
				parse_alternate_access(${pass_msg});
				delete pass_msg;
				break;
			}
		}
		return true;
	%}

	function parse_select_alternate_access(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{	
			// accessSelection
			case 0x81:
				// component
				print_result_to_bytestring("Component", ${msg.content});
				break;
			case 0x82:
				//DEBUG_PRINT("Result: Index tag 0x%x len 0x%x val %ld\n", ${msg.meta.tag}, ${msg.meta.len}, asn1_integer_to_val(${msg}, TYPE_COUNT)->AsCount());
				DEBUG_PRINT("Result: Index tag 0x%x len 0x%x val %u\n", ${msg.meta.tag}, ${msg.meta.len}, binary_to_uint32(${msg.content}));
				break;
			case 0x83:
			{			
				DEBUG_PRINT("Result: Index Range");
				ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
				parse_index_range(${tmp});
				delete tmp;
				break;
			}
			case 0x84:
				DEBUG_PRINT("Result: All Elements NULL\n");
				break;
			
			// selectAccess
			default:
			{
				ASN1Encoding *pass_msg = msg;
				parse_alternate_access(${pass_msg});
				break;
			}
		}
		return true;
	%}

	function parse_select_access(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80:
				// component
				print_asn1_header("MMS component_name meta:", ${msg.meta});
				print_result_to_string("component_name", ${msg.content});
				break;
			case 0x81:
				print_result_to_bytestring("Index", ${msg.content});
				break;
			case 0x82:
			{
				DEBUG_PRINT("Results: Index Range");
				ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
				parse_index_range(${tmp});
				delete tmp;
				break;
			}
			case 0x83:
				print_result_to_bytestring("All Elements", ${msg.content});
				break;
		}
		return true;
	%}

	function parse_index_range(msg: ASN1Encoding): bool
	%{
		// TODO: parse the sequence of lowIndex and numOfElements
		DEBUG_PRINT("Result: Index Range tag 0x%x len 0x%x val ", ${msg.meta.tag}, ${msg.meta.len});
		print_bytestring_full(${msg.content});
		return true;
	%}

	function parse_variable_specification(msg: ASN1Encoding): bool
	%{
		print_asn1_header("MMS variable_specification: ", ${msg.meta});
		ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
		switch(${msg.meta.tag})
		{
			case 0xa0: //name
			{ 
				parse_object_name(${tmp});
				break;
			}
			case 0xa1:
			{ 
				parse_address(${tmp});
				break;
			}
			case 0xa2: 
			{ 
				parse_variable_description(${tmp});
				break;
			}
			case 0xa3:
				{
					const_byteptr moving_target_begin = ${tmp.content}.begin();
					const_byteptr target_end = ${tmp.content}.end();
					
					while(moving_target_begin!=target_end)
					{
						//read the data
						ASN1Encoding tmp;
						tmp.Parse(moving_target_begin, target_end);
						int data_length = tmp.meta()->length();
						int header_length = get_header_bytes(tmp.meta());
						
						parse_scatteredAccessDescription(&tmp);
						moving_target_begin += (data_length + header_length);						
					}
					break;
				}
			case 0xa4:
				DEBUG_PRINT("Result: invalidated \n");
				break;
			case 0xa5:
				parse_alternate_access(${tmp});
				break;
			default:
				DEBUG_PRINT("Unknown MMS variable_specification tag\n");
				break;
		}
		
		delete tmp;
		return true;
	%}

	function parse_object_name(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80:
			{
				print_asn1_header("MMS object_name", ${msg.meta});
				print_result_to_string("basicVMD-specific", ${msg.content});
				break;
			}
			
			case 0xa1:
			{
				//domain_specific
				const_byteptr moving_target_begin = ${msg.content}.begin();
				const_byteptr target_end = ${msg.content}.end();

				ASN1Encoding tmp_domain_id;
				tmp_domain_id.Parse(moving_target_begin, target_end);
				int data_length = tmp_domain_id.meta()->length();
				int header_length = get_header_bytes(tmp_domain_id.meta());
				moving_target_begin += (data_length + header_length);
				
				ASN1Encoding tmp_item_id;
				tmp_item_id.Parse(moving_target_begin, target_end);
				
				string domain_id = std_str(tmp_domain_id.content()).c_str();
				string item_id = std_str(tmp_item_id.content()).c_str();
				DEBUG_COUT("Domain ID: " << domain_id);
				DEBUG_COUT("Item ID: " << item_id);
				
				// Special handling of storage for domain & item id based on originator or responder status
				if(is_request && concatenated_domain_item_id=="")
				{
					set_request_identifier(domain_id + "_" + item_id);
				}
				else
				{
					store_data(domain_id, DATATYPE_VISIBLE_STRING);
					store_data(item_id, DATATYPE_VISIBLE_STRING);
				}
								
			
				break;
			}
				
			case 0x82:
			{
				print_asn1_header("MMS object_name", ${msg.meta});
				print_result_to_string("basicAA-specific", ${msg.content});
				break;
			}

			case 0x83:
			{
				print_asn1_header("MMS object_name", ${msg.meta});
				print_result_to_string("extndVMD-specific", ${msg.content});
				break;
			}

			case 0x84:
			{
				print_asn1_header("MMS object_name", ${msg.meta});
				print_result_to_string("extndAA-specific", ${msg.content});
				break;
			}
		}
		return true;
	%}

	function parse_domainSpecific(msg: ASN1Encoding): bool
	%{
		print_asn1_header("MMS object_name", ${msg.meta});
		print_result_to_string("domain-specific", ${msg.content});
		return true;
	%}

	function parse_address(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0x80: 
				print_asn1_header("Result: Numeric Address", ${msg.meta});
				DEBUG_PRINT("Result: %u\n", binary_to_uint32(${msg.content}));
				store_data(to_string(binary_to_uint32(${msg.content})), DATATYPE_UNSIGNED); //Untested
				break;
			case 0x81:
				print_asn1_header("Result: Symbolic Address", ${msg.meta});
				DEBUG_PRINT("Result: %s\n",std_str(${msg.content}).c_str()); //MMSString
				store_data(std_str(${msg.content}), DATATYPE_MMS_STRING);
				break;
			case 0x82: //OctetString
				print_asn1_header("Result: Unconstrained Address", ${msg.meta});
				string result = parse_octet_string(${msg});
				store_data(result, DATATYPE_OCTET_STRING);
				break;
		}
		print_bytestring_full(${msg.content});
		return true;
	%}

	function parse_variable_description(msg: ASN1Encoding): bool
	%{
		DEBUG_PRINT("MMS variable_description ");
		print_bytestring_full(${msg.content});
		return true;
	%}

	function parse_scatteredAccessDescription(msg: ASN1Encoding): bool
	%{
		ASN1Encoding * tmp = bytestring_to_asn1(${msg.content});
		switch(${msg.meta.tag})
		{
			case 0x80:
			{
				print_asn1_header("MMS component_name meta:", ${msg.meta});
				print_result_to_string("component_name", ${msg.content});
				break;
			}
			case 0xa1:
			{
				parse_variable_specification(${tmp});
				break;
			}
			case 0xa2:
			{
				parse_alternate_access(${tmp});
				break;
			}
		}
		delete tmp;
		return true;
	%}

	# This function is currently unused
	function parse_mms_file_directory(msg: ASN1Encoding): bool
	%{
		ASN1Encoding *tmp = bytestring_to_asn1(${msg.content});
		switch(${msg.meta.tag})
		{
			case 0xa0:
				print_result_to_string("file_spec", ${tmp.content}); //OPTIONAL
				break;
			case 0xa1:
				print_result_to_string("continue_after", ${tmp.content}); //OPTIONAL
				break;
			default:
				DEBUG_PRINT("MMS file_directory UNKNOWN\n");
				break;
		}
		delete tmp;
		return true;
	%}

	function parse_read_journal_optional(msg: ASN1Encoding): bool
	%{
		switch(${msg.meta.tag})
		{
			case 0xa1:
				DEBUG_PRINT("rangeStartSpec\n");
				break;
			case 0xa2:
				DEBUG_PRINT("rangeStopSpec\n");
				break;
			case 0xa4:
				DEBUG_PRINT("listOfVariables\n");
				break;
			case 0xa5:
				DEBUG_PRINT("endtryToStartAfter\n");
				break;
		}
		return true;
	%}

	function parse_bit_string(msg: ASN1Encoding): string
	%{
		unsigned padding = unsigned(${msg.content}[0]);
		bytestring bs_no_padding_byte(${msg.content}.begin()+1, ${msg.content}.end());
		string result = "";
		
		//byte by byte processing
		for (int i = 0; i < bs_no_padding_byte.length(); ++i )
		{
			uint64 byte = bs_no_padding_byte[i];
			std::bitset<8> bit_string (byte);
			result+=bit_string.to_string();
		}
		
		result = result.substr(0, result.length()-padding);
		// There can be bitstrings of variable lengths with all 0. Retain the length instead of compressing to 0.
		//if(result.length()>0 && result.find('1')==string::npos) result = "0";
		
		DEBUG_COUT("Result: Bit String --> " << result);
		bs_no_padding_byte.free();
		return result;
	%}
	
	function parse_octet_string(msg: ASN1Encoding): string
	%{
		bytestring const& bs = ${msg.content};
		stringstream string_builder;
		string_builder << "";
		for(unsigned i = 0; i < ${msg.meta.length}; i++){
			string_builder << std::hex << setfill('0') << setw(2) << unsigned(bs[i]);
		}
		
		string result = string_builder.str();
		DEBUG_COUT("Result: Octet String --> " << result);
		return result;
	%}

	#================================= ASN1 Conversion Functions =================================
	function binary_to_uint32(bs: bytestring): uint32
		%{
		uint32 rval = 0;
	
		for ( int i = 0; i < bs.length(); ++i )
		{
			uint32 byte = bs[i];
			rval |= byte << (8 * (bs.length() - (i + 1)));
		}
	
		return rval;
		%}
	
	# Up to 64-bits
	function binary_to_unsigned_int(bs: bytestring): uint64
	%{
		uint64 rval = 0;
	
		for ( int i = 0; i < bs.length(); ++i )
		{
			uint64 byte = bs[i];
			rval |= byte << (8 * (bs.length() - (i + 1)));
		}
	
		return rval;		
	%}
	
	function binary_to_signed_int(bs: bytestring): int64
	%{	
		int64 res = binary_to_int64(bs); //returns 0-padded result if <64 bits

		// if MSB is negative, pad preceding bits with 1.
		int len = bs.length();
		if(len>0 && bs[0]&0x80)
		{
			uint64 padding = 0xff;
			for(int i=0; i<(8-len); i++)
			{
				res |= (padding << ((i+len)*8));
			}
		}
		
		return res;
	%}
	
	function binary_to_boolean(bs: bytestring): string
	%{
		return (binary_to_uint32(bs))?"true":"false";
	%}

	#================================= Utility Functions =================================
	function get_header_bytes(msg: ASN1EncodingMeta): uint32
	%{
		if (${msg.long_len==1})
			return ${msg.more_len}.length() + 2;
		else
			return 2;
	%}

	function get_ASN1Encoding_bytes(msg: ASN1EncodingMeta): uint64
	%{
		return (get_header_bytes(${msg}) + ${msg.length});
	%}

	function print_bytestring(b:bytestring, start:int, len:int): bool
	%{
		if(b.length()>=len)
		{
			for(int i=start; i<len; i++)
			{
				DEBUG_PRINT("0x%02x ", ${b[i]});
				if((i+1)%20==0 && i!=len-1) DEBUG_PRINT("\n");
			}
			DEBUG_PRINT("\n");
		}
		
		return true;
	%}
	
	function print_bytestring_full(b:bytestring): bool
	%{
		print_bytestring(b, 0, b.length());
		return true;
	%}
	
	function print_asn1_header(s: string, a: ASN1EncodingMeta): bool
	%{
		DEBUG_PRINT("%s tag 0x%x len 0x%x\n", s.c_str(), ${a.tag}, ${a.len});
		return true;
	%}

	function bytestring_to_asn1(b: bytestring): ASN1Encoding
	%{
		const_byteptr moving_target_begin = b.begin();
		const_byteptr target_end = b.end();
				
		ASN1Encoding * tmp = new ASN1Encoding();
		tmp->Parse(moving_target_begin, target_end);
		return tmp;
	%}

	function print_result_to_bytestring(s: string, b: bytestring): bool
	%{
		DEBUG_PRINT("Result: %s --> ", s.c_str());
		print_bytestring_full(b);	
		return true;
	%}

	function print_result_to_string(s: string, b: bytestring): bool
	%{
		DEBUG_PRINT("Result: %s --> %s\n", s.c_str(), std_str(b).c_str());
		return true;
	%}

	function proc_mms_remaining_length(length: uint64, a: ASN1EncodingMeta): uint64
	%{
		if (length == 0) return 0;
		int data_length = ${a.length};
		int header_length = get_header_bytes(${a});
		length -= (header_length + data_length);
		
		return length;
	%}

	function proc_mms_remaining_check(length: uint64, a: ASN1EncodingMeta): bool
	%{
		int result = proc_mms_remaining_length(length, a);
		if (result>0) {
			return 1;
		} else {
			return 0;
		}
	%}

	function set_request_identifier(id: string): bool
	%{
		concatenated_domain_item_id = id;	
		return true;
	%}
	
	function set_service(id: int32): bool
	%{
		this->connection()->upflow()->service = id;
		return true;
	%}
	
	function store_data(str_input: string, datatype: int32): bool
	%{
		this->connection()->upflow()->current_pdu_data_pair_vector.emplace_back(std::make_pair(str_input, datatype));
		
		return true;
	%}
	
	function update_event_params(vec_data: VectorVal, vec_datatype: VectorVal): bool
	%{
		int i = 0;
		for(auto& p: this->connection()->upflow()->current_pdu_data_pair_vector)
		{
			vec_data->Assign(i, new StringVal(p.first));
			vec_datatype->Assign(i, new Val(p.second, TYPE_COUNT));
			++i;
		}
		return true;
	%}
}