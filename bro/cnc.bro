redef signature_files += "cnc.sig";

module CNC;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		CNC_Contacted,	# the source has contacted a blacklisted C&C server
	};

	type Info: record {
		ts:            time               &log;
		uid:           string             &log;
		id:            conn_id            &log;
		proto:         transport_proto    &log;
	};

	global log_cnc: event(rec: Info);
}

event bro_init()
{
	Log::create_stream(CNC::LOG, [$columns=Info, $ev=log_cnc]);
}

event signature_match(state: signature_state, msg: string, data: string)
	{
		if ( msg == /cnc.*/ )
			{
			local c: connection = state$conn;
			local info: Info;

			info$ts       = network_time();
			info$id       = c$id;
			info$uid      = c$uid;
			info$proto    = get_conn_transport_proto(c$id);

			Log::write(CNC::LOG, info);
			}
	}

