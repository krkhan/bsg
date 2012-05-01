##! This script analyzes the egg-download phase of botnet infection lifecycle.
##! It sets a threshold on the number of malicious binaries seen and
##! the number of exes trasported over http disguised as some other filetype
##! and uses the evaluate() function to decide if the major event egg_download 
##! should be triggered.

@load base/protocols/http
@load protocols/http/detect-MHR
@load botflex/utils/types
@load botflex/config

module Egg;

export {
	redef enum Log::ID += { LOG_DOWN, LOG_UP };

	type Info: record {
		ts:                	time             &log;
		src_ip:            	addr             &log;
		summary:                string  	 &log;
		msg:  	 	        string  	 &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;};

	## A structure to hold a url along with its md5 hash
	type IpUrlMD5Record: record {
	    ip: addr;
	    url: string &default="";
	    md5: string &default="";	
	};

	## The contributory factors (or tributaries) to major event egg_download/upload
	type egg_tributary: enum { Tcymru_match, Disguised_exe };

	## Expire interval for the global table concerned with maintaining egg_download/upload info
	const wnd_egg = 15mins &redef;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	const egg_evaluation_mode = OR;

	## The table that maps egg_tributary enum values to strings
	global tb_tributary_string: table[ egg_tributary ] of string &redef; 

	## Thresholds for different contributors to the major event of egg download/upload
	const tcymru_match_threshold = 0 &redef;
	const disguised_exe_threshold = 0 &redef;

	## The event that sufficient evidence has been gathered to declare the
	## egg download phase of botnet infection lifecycle
	global egg_download: event( ts: time, src_ip: addr, malicious_ips: set[IpUrlMD5Record] );

	## The event that sufficient evidence has been gathered to declare the
	## egg upload tributary in attack phase of botnet infection lifecycle
	global egg_upload: event( ts: time, src_ip: addr, malicious_ips: set[IpUrlMD5Record] );

	## Event that can be handled to access the egg_download
	## record as it is sent on to the logging framework.
	global log_egg_download: event(rec: Info);

	## Event that can be handled to access the egg_upload
	## record as it is sent on to the logging framework.
	global log_egg_upload: event(rec: Info);

}


## The event that an exe was trasported over http with some other extension. 
## This is a common approach for delivering malicious binaries to victim machines
global disguised_exe: event( ts: time, src_ip: addr, dst_ip: addr, url: string );

## The event that the md5 hash of an exe matched Team Cymru's malware hash repository
## For more information, please refer to /policy/protocols/http/detect-MHR
global tcymru_match: event( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string );

## Hooking into the notices HTTP::Incorrect_File_Type and HTTP::Malware_Hash_Registry_Match
## to generate sub-events that contribute to the major events egg download/upload

redef Notice::policy += {
       [$pred(n: Notice::Info) = {  
               if ( n$note == HTTP::Incorrect_File_Type && ( /application\/x-dosexec/ in n$msg || /application\/x-executable/ in n$msg ) )
                       {
			local c = n$conn;
			event Egg::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, HTTP::build_url_http(c$http) );
                       }

               else if ( n$note == HTTP::Malware_Hash_Registry_Match )
                       {
			## FIXME: This is a hack to get md5 and url as n$conn$http is uninitialized at this stage
			## As per /policy/protocols/http/detect-MHR, msg_arr[1]=src_ip, msg_arr[2]=md5, msg_arr[3]=url
			local msg_arr = split(n$msg, /[[:blank:]]*/);

			event Egg::tcymru_match( n$ts, n$src, n$dst, msg_arr[3], msg_arr[2] );
                       }
	
       }]
};

## Type of the value of the global table table_egg
## Additional contributary factors that increase the confidence
## about major event egg_download/upload should be added here 
type EggRecord: record {
    tb_tributary: table[ egg_tributary ] of bool;
    n_tcymru_matches: count &default=0;
    n_disguised_exes: count &default=0;	
    ip_url_md5: set[IpUrlMD5Record] &optional;  	
};


event bro_init() &priority=5
	{
	Log::create_stream(Egg::LOG_DOWN, [$columns=Info, $ev=log_egg_download]);
	Log::create_stream(Egg::LOG_UP, [$columns=Info, $ev=log_egg_upload]);

	if ( "egg-download" in Config::table_config  )
			{
			if ( "th_disguised_exe" in Config::table_config["egg-download"] )
				{
				disguised_exe_threshold = to_count(Config::table_config["egg-download"]["th_disguised_exe"]);
				}
			if ( "th_tcymru_match" in Config::table_config["egg-download"] )
				{
				tcymru_match_threshold = to_count(Config::table_config["egg-download"]["th_tcymru_match"]);
				}
			if ( "wnd_egg" in Config::table_config["egg-download"] )
				{
				wnd_egg = string_to_interval(Config::table_config["egg-download"]["wnd_egg"]);
				}
			if ( "evaluation_mode" in Config::table_config["egg-download"] )
				{
				egg_evaluation_mode = string_to_evaluationmode(Config::table_config["egg-download"]["evaluation_mode"]);
				}	
			}
	## Map all possible values of enum cnc_tributary to corresponding strings
	## here. This table will be used to formulate a human readable string for sharing 
	## with other scripts.
	tb_tributary_string[ Tcymru_match ] = "Saw malicious exe file (TeamCymru match)";
	tb_tributary_string[ Disguised_exe ] = "Saw a disguised exe file";
	}
global egg_info: Egg::Info;

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[egg_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[egg_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[egg_tributary] of bool ): bool
	{
	local t = 0;
	local f = 0;
	for ( rec in tb )
		{
		if ( tb[rec] )
			++t;
		else
			++f;
		}

	if ( f > t )
		return F;
	else
		return T;
	}

## The function that decides whether or not the major event egg_download/upload 
## should be generated. It is called (i) every time an entry in the global table 
## table_egg reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 
function evaluate( src_ip: addr, t: table[addr] of EggRecord )
	{
	local do_report: bool;
	if ( egg_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( egg_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( egg_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{ print "Do report";
		## Log egg download related entries
		egg_info$ts = network_time();
		egg_info$src_ip = src_ip;
		local summ = "";
		for (rec in t[src_ip]$ip_url_md5)
			{
			summ = summ + fmt("[ %s, %s, %s ] ",rec$ip, rec$url, rec$md5 );
			} 
		egg_info$summary = summ;
		## Other contributory factors to the event egg down/upload should
		## be appended to this msg.
		local mesg = "";
		for ( itm in t[src_ip]$tb_tributary )
			mesg = mesg + tb_tributary_string[itm] + ",";
		egg_info$msg = mesg;
		
		local outbound = Site::is_local_addr(src_ip);
		print "outbound";print outbound;print "--------------";
		if ( !outbound )
			{
    			event egg_download( network_time(), src_ip, t[src_ip]$ip_url_md5);
			Log::write(Egg::LOG_DOWN,egg_info);
			}
		else
			{
    			event egg_upload( network_time(), src_ip, t[src_ip]$ip_url_md5);
			Log::write(Egg::LOG_UP,egg_info);
			}

		delete t[src_ip];
		print t;
		}
	}


## Called when an entry in the global table table_egg exceeds certain age, as specified
## in the table attribute create_expire.
function egg_record_expired(t: table[addr] of EggRecord, idx: any): interval
	{
	evaluate( idx, t );
	return 0secs;
	}

function get_egg_record(): EggRecord
	{
	local rec: EggRecord;

	local u: set[IpUrlMD5Record];
	rec$ip_url_md5 = u; 

	return rec;
	}

## The global state table that maintains various information pertaining to the
## major event egg_down/upload, and is analyzed when a decision has to be made
## whether or not to declare the major event egg_down/upload.
global table_egg: table[addr] of EggRecord &create_expire=30mins &expire_func=egg_record_expired;

event tcymru_match( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string )
	{
	## src_ip seen for the first time
	if (src_ip !in table_egg)
		table_egg[src_ip] = get_egg_record();

	# Update total number of malicious binary downloads seen
	++ table_egg[src_ip]$n_tcymru_matches;

	add table_egg[src_ip]$ip_url_md5[ [ $ip = dst_ip, $url = url, $md5 = md5 ] ];

	if( table_egg[src_ip]$n_tcymru_matches > tcymru_match_threshold )
		{
		table_egg[src_ip]$tb_tributary[ Tcymru_match ]=T;
		Egg::evaluate( src_ip, table_egg );
		}	
	}


event disguised_exe( ts: time, src_ip: addr, dst_ip: addr, url: string )
	{
	## src_ip seen for the first time
	if (src_ip !in table_egg)
		table_egg[src_ip] = get_egg_record();

	# Update total number of disguised exes seen
	++ table_egg[src_ip]$n_disguised_exes;

	add table_egg[src_ip]$ip_url_md5[ [ $ip = dst_ip , $url = url, $md5 = "-" ] ];

	if( table_egg[src_ip]$n_disguised_exes > disguised_exe_threshold )
		{
		table_egg[src_ip]$tb_tributary[ Disguised_exe ]=T;
		Egg::evaluate( src_ip, table_egg );
		}
	}
