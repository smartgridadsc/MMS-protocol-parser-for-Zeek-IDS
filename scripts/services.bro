module MMS;

event get_name_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "getNameList";
	if(identifier != "") print "identifier", identifier;
	
	for (i in data_vec)
		print "data", data_vec[i];	
}

event get_name_list_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "getNameList";
	if(identifier != "") print "identifier", identifier;

	for (i in data_vec)
		print "data", data_vec[i];	
}

event read_request(c: connection, invoke_id: count, identifier: string){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "read";
	print "identifier", identifier;	
}

event read_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "read";
	print "identifier", identifier;	

	for (i in data_vec)
		print "data", data_vec[i];		
}

event write_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "write";
	print "identifier", identifier;

	for(i in data_vec)
	{	
		print "data", data_vec[i];
	}	
}

event write_response(c: connection, invoke_id: count, identifier: string){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "write";
	print "identifier", identifier;
}

event get_var_access_attr_request(c: connection, invoke_id: count, identifier: string){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "getVariableAccessAttributes";
	print "identifier", identifier;
}

event get_var_access_attr_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "getVariableAccessAttributes";
	print "identifier", identifier;

	for (i in data_vec)
		print "data", data_vec[i];	
}

event get_named_var_list_attr_request(c: connection, invoke_id: count, identifier: string){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "getNamedVariableListAttributes";
	print "identifier", identifier;
}

event get_named_var_list_attr_response(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "getNamedVariableListAttributes";
	print "identifier", identifier;

	for (i in data_vec)
		print "data", data_vec[i];
}

event status_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "status";
	
	for (i in data_vec)
		print "data", data_vec[i];	
}

event status_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "status";

	for (i in data_vec)
		print "data", data_vec[i];
}

event conclude_request(c: connection){
	print "direction", "request";
	print "service", "conclude";
}

event conclude_response(c: connection){
	print "direction", "response";
	print "service", "conclude";
}

event file_directory_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "fileDirectory";

	if(|data_vec|!=0)
	{
		for (i in data_vec)
			print "data", data_vec[i];
	}
}

event file_directory_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "fileDirectory";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_open_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "fileOpen";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_open_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "fileOpen";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_read_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "fileRead";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_read_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "fileRead";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_close_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "fileClose";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_close_response(c: connection, invoke_id: count){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "fileClose";
}

event file_rename_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "fileRename";

	for (i in data_vec)
		print "data", data_vec[i];
}

event file_rename_response(c: connection, invoke_id: count){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "fileRename";
}

event identify_request(c: connection, invoke_id: count){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "identify";
}

event identify_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "identify";

	for (i in data_vec)
		print "data", data_vec[i];
}

event define_named_var_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "defineNamedVariableList";
	print "identifier", identifier;

	for (i in data_vec)
		print "data", data_vec[i];	
}

event define_named_var_list_response(c: connection, invoke_id: count){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "defineNamedVariableList";
}

event delete_named_var_list_request(c: connection, invoke_id: count, identifier: string, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "deleteNamedVariableList";
	print "identifier", identifier;

	for (i in data_vec)
		print "data", data_vec[i];	
}

event delete_named_var_list_response(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "deleteNamedVariableList";

	for (i in data_vec)
		print "data", data_vec[i];	
}

event initiate_request(c: connection, data_vec: string_vec, datatype_vec: index_vec){
	print "direction", "request";
	print "service", "initiate";

	for (i in data_vec)
		print "data", data_vec[i];	
}

event initiate_response(c: connection, data_vec: string_vec, datatype_vec: index_vec){
	print "direction", "response";
	print "service", "initiate";

	for (i in data_vec)
		print "data", data_vec[i];	
}

event obtain_file_request(c: connection, invoke_id: count, data_vec: string_vec, datatype_vec: index_vec){
	print "invokeId", invoke_id;
	print "direction", "request";
	print "service", "obtainFile";

	for (i in data_vec)
		print "data", data_vec[i];	
}

event obtain_file_response(c: connection, invoke_id: count){
	print "invokeId", invoke_id;
	print "direction", "response";
	print "service", "obtainFile";
}
