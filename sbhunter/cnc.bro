module CNC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		dns_failures:	   count	    &log;
		ip_cnc_list:	   string           &log;
		url_cnc_list:	   string           &log; 
	};
	
	redef record connection += {
	conn: Info &optional;};

	## Thresholds for different contributors to the major event cnc
	const dns_failure_threshold = 1 &redef;
	const blacklist_match_threshold = 2 &redef;

	## Event that can be handled to access the cnc
	## record as it is sent on to the logging framework.
	global log_cnc: event(rec: Info);
}

## Type of the value of the global table table_cnc
## Additional contributary factors that increase the confidence
## about major event egg_download should be added here 
type CncRecord: record {
    n_dns_failures: count;
    n_blacklist_matches: count;	
    ip_cnc: set[addr];
    url_cnc: set[string];  	
};

## The event that sufficient evidence has been gathered to declare the
## CnC phase of botnet infection lifecycle
global cnc: event( ts: time, src_ip: addr, n_dns_failures: count, n_blacklist_matches: count, ip_cnc: set[addr], url_cnc: set[string] );

## The event that 'dns_failure_threshold' number of failed dns queries
## were observed. This may hint at the use of domain flux as in the case
## of certain botnets such as Torpig and Conficker 
global dns_failure: event( ts: time, src_ip: addr );

## The event that a host was found to communicate with CnC server ip
## or url from our blacklists
global cnc_url_match: event( ts: time, src_ip: addr, cnc_url: string );

## The event that a host was found to communicate with CnC server ip
## from our blacklists
global cnc_ip_match: event( ts: time, src_ip: addr, cnc_ip: addr );

event bro_init() &priority=5
	{
	Log::create_stream(CNC::LOG, [$columns=Info, $ev=log_cnc]);
	}
global cnc_info: CNC::Info;

## The function that decides whether or not the major event cnc should
## be generated. It is called (i) every time an entry in the global table table_cnc
## reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 

function evaluate( src_ip: addr, t: table[addr] of CncRecord )
	{
	if( t[src_ip]$n_dns_failures > dns_failure_threshold || t[src_ip]$n_blacklist_matches > blacklist_match_threshold )
		{
  
    		event CNC::cnc( network_time(), src_ip, t[src_ip]$n_dns_failures, t[src_ip]$n_blacklist_matches, t[src_ip]$ip_cnc, t[src_ip]$url_cnc);		
	
		## Log cnc related entries
		cnc_info$ts = network_time();
		cnc_info$src_ip = src_ip;
		cnc_info$dns_failures = t[src_ip]$n_dns_failures;
		local message = "";
		for ( rec in t[src_ip]$ip_cnc )
			{
			message = message + fmt("%s",rec);
			} 
		cnc_info$ip_cnc_list = message;
		message="";
		for ( r in t[src_ip]$url_cnc )
			{
			message = message + r;
			} 

		cnc_info$url_cnc_list = message;
		Log::write(CNC::LOG,cnc_info);

		## Get rid of the record
		delete t[src_ip];
		}
	

	
	}


## Called when an entry in the global table table_cnc exceeds certain age, as specified
## in the table attribute create_expire.
function cnc_record_expired(t: table[addr] of CncRecord, idx: any): interval
	{
	evaluate( idx, t );
	return 0secs;
	}


## The global state table that maintains various information pertaining to the
## major event cnc, and is analyzed when a decision has to be made whether
## or not to declare the major event cnc.
global table_cnc: table[addr] of CncRecord &create_expire=55mins &expire_func=cnc_record_expired;


event CNC::dns_failure( ts: time, src_ip: addr )
	{
	if (src_ip !in table_cnc)
		{
		local rec: CncRecord;
		rec$n_blacklist_matches=0;
		rec$n_dns_failures=0;
		local s_ip: set[addr]; 
		rec$ip_cnc = s_ip;
		local s_url: set[string]; 
		rec$url_cnc = s_url;

		table_cnc[src_ip] = rec;
			
		}

	# Update total number of failed dns queries
	++ table_cnc[src_ip]$n_dns_failures;

	if( table_cnc[src_ip]$n_dns_failures >= dns_failure_threshold )
		evaluate( src_ip, table_cnc );	
	}


event CNC::cnc_url_match( ts: time, src_ip: addr, cnc_url: string )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		{
		local rec: CncRecord;
		rec$n_blacklist_matches=0;
		rec$n_dns_failures=0;
		local s_ip: set[addr]; 
		rec$ip_cnc = s_ip;
		local s_url: set[string]; 
		rec$url_cnc = s_url;

		table_cnc[src_ip] = rec;	
		}

	# Update total number of malicious binary downloads seen
	++ table_cnc[src_ip]$n_blacklist_matches;

	add table_cnc[src_ip]$url_cnc[ cnc_url ];

	if( table_cnc[src_ip]$n_blacklist_matches >= blacklist_match_threshold )
		evaluate( src_ip, table_cnc );	
	}


event CNC::cnc_ip_match( ts: time, src_ip: addr, cnc_ip: addr )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		{
		local rec: CncRecord;
		rec$n_blacklist_matches=0;
		rec$n_dns_failures=0;
		local s_ip: set[addr]; 
		rec$ip_cnc = s_ip;
		local s_url: set[string]; 
		rec$url_cnc = s_url;

		table_cnc[src_ip] = rec;	
		}

	# Update total number of malicious binary downloads seen
	++ table_cnc[src_ip]$n_blacklist_matches;

	add table_cnc[src_ip]$ip_cnc[ cnc_ip ];

	if( table_cnc[src_ip]$n_blacklist_matches >= blacklist_match_threshold )
		evaluate( src_ip, table_cnc );	
	}

## Handling the default dns_message event to detect dns NXDOMAIN replies
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local id = c$id;
	if ( msg$rcode == 3 )
		{
		event CNC::dns_failure(c$start_time, id$orig_h);
		}
	}

