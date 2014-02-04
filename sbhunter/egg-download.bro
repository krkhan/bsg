##! This script analyzes the egg-download phase of botnet infection lifecycle.
##! It sets a threshold on the number of malicious binaries seen and
##! the number of exes trasported over http disguised as some other filetype
##! and uses the evaluate() function to decide if the major event egg_download 
##! should be triggered.

@load base/protocols/http
@load protocols/http/detect-MHR
module Egg_Download;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		msg:		   string	    &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;};

	## Thresholds for different contributors to the major event of egg download
	const tcymru_match_threshold = 0 &redef;
	const disguised_exe_threshold = 0 &redef;

	## Event that can be handled to access the egg_download
	## record as it is sent on to the logging framework.
	global log_egg_download: event(rec: Info);
}

## A structure to hold a url along with its md5 hash
type IpUrlMD5Record: record {
    ip: addr;
    url: string;
    md5: string;	
};

## The event that an exe was trasported over http with some other extension. 
## This is a common approach for delivering malicious binaries to victim machines
global disguised_exe: event( ts: time, src_ip: addr, dst_ip: addr, url: string );

## The event that the md5 hash of an exe matched Team Cymru's malware hash repository
## For more information, please refer to /policy/protocols/http/detect-MHR
global tcymru_match: event( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string );

## The event that sufficient evidence has been gathered to declare the
## egg download phase of botnet infection lifecycle
global egg_download: event( ts: time, src_ip: addr, malicious_ips: set[IpUrlMD5Record] );

## Hooking into the notices HTTP::Incorrect_File_Type and HTTP::Malware_Hash_Registry_Match
## to generate sub-events that contribute to the major event egg download

redef Notice::policy += {
       [$pred(n: Notice::Info) = {  
               if ( n$note == HTTP::Incorrect_File_Type && ( /application\/x-dosexec/ in n$msg || /application\/x-executable/ in n$msg ) )
                       {
			local c = n$conn;
			event Egg_Download::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, HTTP::build_url_http(c$http) );
                       }

               else if ( n$note == HTTP::Malware_Hash_Registry_Match )
                       {
			## FIXME: This is a hack to get md5 and url as n$conn$http is uninitialized at this stage
			## As per /policy/protocols/http/detect-MHR, msg_arr[1]=src_ip, msg_arr[2]=md5, msg_arr[3]=url
			local msg_arr = split(n$msg, /[[:blank:]]*/);

			event Egg_Download::tcymru_match( n$ts, n$src, n$dst, msg_arr[3], msg_arr[2] );
                       }
	
       }]
};

## Type of the value of the global table table_egg
## Additional contributary factors that increase the confidence
## about major event egg_download should be added here 
type EggRecord: record {
    n_tcymru_matches: count;
    n_disguised_exes: count;	
    ip_url_md5: set[IpUrlMD5Record] &optional;  	
};


event bro_init() &priority=5
	{
	Log::create_stream(Egg_Download::LOG, [$columns=Info, $ev=log_egg_download]);
	}
global egg_download_info: Egg_Download::Info;


## The function that decides whether or not the major event egg_download should
## be generated. It is called (i) every time an entry in the global table table_egg
## reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 

function evaluate( src_ip: addr, t: table[addr] of EggRecord )
	{
	if( t[src_ip]$n_tcymru_matches > tcymru_match_threshold || t[src_ip]$n_disguised_exes > disguised_exe_threshold ) 
		{ 
    		event egg_download( network_time(), src_ip, t[src_ip]$ip_url_md5);
		print t;
		## Log egg download related entries
		egg_download_info$ts= network_time();
		egg_download_info$src_ip= src_ip;
		local message = "";
		for (rec in t[src_ip]$ip_url_md5)
			{
			message = message + fmt("[ %s, %s, %s ] ",rec$ip, rec$url, rec$md5 );
			} 
		egg_download_info$msg = message;
		Log::write(Egg_Download::LOG,egg_download_info);

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

## The global state table that maintains various information pertaining to the
## major event egg_download, and is analyzed when a decision has to be made whether
## or not to declare the major event egg_download.
global table_egg: table[addr] of EggRecord &create_expire=30mins &expire_func=egg_record_expired;

event tcymru_match( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string )
	{
	print "tc match";
	print url;
	## src_ip seen for the first time
	if (src_ip !in table_egg)
		{
		local rec: EggRecord;
		rec$n_tcymru_matches=0;
		rec$n_disguised_exes=0;
		local u: set[IpUrlMD5Record]; 
		rec$ip_url_md5 = u;
		table_egg[src_ip]=rec;
			
		}

	# Update total number of malicious binary downloads seen
	++ table_egg[src_ip]$n_tcymru_matches;

	add table_egg[src_ip]$ip_url_md5[ [ $ip = dst_ip, $url = url, $md5 = md5 ] ];

	if( table_egg[src_ip]$n_tcymru_matches > tcymru_match_threshold )
		Egg_Download::evaluate( src_ip, table_egg );	
	}


event disguised_exe( ts: time, src_ip: addr, dst_ip: addr, url: string )
	{
	print "disguised thing";
	print url;
	if (src_ip !in table_egg)
		{
		local rec: EggRecord;
		rec$n_tcymru_matches=0;
		rec$n_disguised_exes=0;
		local u: set[IpUrlMD5Record]; 
		rec$ip_url_md5 = u;

		table_egg[src_ip] = rec;
			
		}

	# Update total number of disguised exes seen
	++ table_egg[src_ip]$n_disguised_exes;

	add table_egg[src_ip]$ip_url_md5[ [ $ip = dst_ip , $url = url, $md5 = "-" ] ];

	if( table_egg[src_ip]$n_disguised_exes > disguised_exe_threshold )
		Egg_Download::evaluate( src_ip, table_egg );
	}
