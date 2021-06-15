module MMS;

redef enum Log::ID += { LOG };

type Info: record {
	## Timestamp for when the event happened.
	ts: time &log;

	## MMS service name
	service: string &log;
	
	## Request or response
	direction: string &log;
	
	## Invoke ID of MMS confirmed service	
	invoke_id: count &log &optional;
	
	## An object identifier in the request
	identifier: string &log &optional;
	
	## Data retrieved from packet
	data:  vector of string &log &optional;
};

## Event to access the MMS record as it is sent on to the logging framework.
global log_mms: event(rec: Info);

event bro_init() &priority=5 {
		Log::create_stream(LOG, [$columns=Info, $ev=log_mms, $path="mms"]);
}

event get_name_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="get_name_list", $direction="request", 
		$invoke_id=invoke_id, $identifier=identifier];
	Log::write(MMS::LOG, info);
}

event get_name_list_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="get_name_list", $direction="response",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event read_request(c: connection, invoke_id: count, identifier: string){
	local info: Info = [$ts=network_time(), $service="read", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier];
	Log::write(MMS::LOG, info);
}

event read_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="read", $direction="response",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event write_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="write", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event write_response(c: connection, invoke_id: count, identifier: string){
	local info: Info = [$ts=network_time(), $service="write", $direction="response",
		$invoke_id=invoke_id, $identifier=identifier];
	Log::write(MMS::LOG, info);
}

event get_var_access_attr_request(c: connection, invoke_id: count, identifier: string){
	local info: Info = [$ts=network_time(), $service="get_var_access_attr", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier];
	Log::write(MMS::LOG, info);
}

event get_var_access_attr_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="get_var_access_attr", $direction="response",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event get_named_var_list_attr_request(c: connection, invoke_id: count, identifier: string){
	local info: Info = [$ts=network_time(), $service="get_named_var_list_attr", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier];
	Log::write(MMS::LOG, info);
}

event get_named_var_list_attr_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="get_named_var_list_attr", $direction="response",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event status_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="status", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event status_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="status", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event conclude_request(c: connection){
	local info: Info = [$ts=network_time(), $service="conclude", $direction="request"];
	Log::write(MMS::LOG, info);
}

event conclude_response(c: connection){
	local info: Info = [$ts=network_time(), $service="conclude", $direction="response"];
	Log::write(MMS::LOG, info);
}

event file_directory_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_directory", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_directory_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_directory", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_open_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_open", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_open_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_open", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_read_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_read", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_read_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_read", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_close_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_close", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_close_response(c: connection, invoke_id: count){
	local info: Info = [$ts=network_time(), $service="file_close", $direction="response",
		$invoke_id=invoke_id];
	Log::write(MMS::LOG, info);
}

event file_rename_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="file_rename", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event file_rename_response(c: connection, invoke_id: count){
	local info: Info = [$ts=network_time(), $service="file_rename", $direction="response",
		$invoke_id=invoke_id];
	Log::write(MMS::LOG, info);
}

event identify_request(c: connection, invoke_id: count){
	local info: Info = [$ts=network_time(), $service="identify", $direction="request",
		$invoke_id=invoke_id];
	Log::write(MMS::LOG, info);
}

event identify_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="identify", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event define_named_var_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="define_named_var_list", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event define_named_var_list_response(c: connection, invoke_id: count){
	local info: Info = [$ts=network_time(), $service="define_named_var_list", $direction="response",
		$invoke_id=invoke_id];
	Log::write(MMS::LOG, info);
}

event delete_named_var_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="delete_named_var_list", $direction="request",
		$invoke_id=invoke_id, $identifier=identifier, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event delete_named_var_list_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="delete_named_var_list", $direction="response",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event initiate_request(c: connection, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="initiate", $direction="request",
		$data=data_vec];
	Log::write(MMS::LOG, info);
}

event initiate_response(c: connection, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="initiate", $direction="response",
		$data=data_vec];
	Log::write(MMS::LOG, info);
}

event obtain_file_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	local info: Info = [$ts=network_time(), $service="obtain_file", $direction="request",
		$invoke_id=invoke_id, $data=data_vec];
	Log::write(MMS::LOG, info);
}

event obtain_file_response(c: connection, invoke_id: count){
	local info: Info = [$ts=network_time(), $service="obtain_file", $direction="response",
		$invoke_id=invoke_id];
	Log::write(MMS::LOG, info);
}
