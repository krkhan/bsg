##! This script analyzes spam activity in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by setting a threshold on the total number
##! of mx queries made, unique mx queries and total number
##! of smtp queries. 

@load ./bot-attack

module Spam;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:		   addr		    &log;
		total_mx:          count            &log;
		uniq_mx:           count            &log;
		total_smtp:	   count 	    &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_spam: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	const uniq_mx_threshold = 1 &redef;
	const total_mx_threshold = 1 &redef;
	const total_smtp_threshold = 1 &redef;
       }

global spam_info:Spam::Info;

event bro_init() &priority=5
	{
	Log::create_stream(Spam::LOG, [$columns=Info, $ev=log_spam]);
	}

## Type of the value of the global table table_spam
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here
type SpamRecord: record {
    uniq_mx:set[string];
    total_mx:count;
    uniq_smtp: set[conn_id];
    uniq_mx_threshold_crossed: bool;
    total_mx_threshold_crossed: bool;
    _mx_threshold_crossed: bool;	
};


function evaluate_spam( src_ip: addr, t: table[addr] of SpamRecord  )
	{
	local s = t[src_ip];
	if  ( |s$uniq_smtp| > total_smtp_threshold || s$total_mx > total_mx_threshold || |s$uniq_mx| > uniq_mx_threshold )
		{
		event Bot_Attack::spam( src_ip );

		## Log spam-related entries
		spam_info$ts = network_time();
		spam_info$src_ip = src_ip;
		spam_info$uniq_mx = |t[src_ip]$uniq_mx|;
		spam_info$total_mx = t[src_ip]$total_mx;
		spam_info$total_smtp = |t[src_ip]$uniq_smtp|;

		Log::write(Spam::LOG,spam_info);

		delete t[src_ip];
		}		
	}

## Called when an entry in the global table table_spam exceeds certain age, as specified
## in the table attribute create_expire.
function spam_record_expired(t: table[addr] of SpamRecord, idx: any): interval
	{
	evaluate_spam(idx, t);
	return 0secs;
	}

# The global state table that maintains various information pertaining to the
## major event bot_attack, and is analyzed when a decision has to be made whether
## or not to declare the major event bot_attack.
global table_spam: table[addr] of SpamRecord &create_expire=2mins &expire_func=spam_record_expired;	

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{	
	if(c$dns$qtype_name == "MX")
		{
		local src_ip = c$dns$id$orig_h;

		if (src_ip !in table_spam)
			{
			local rec: SpamRecord;
			rec$total_mx=0;
			local set_mx_uniq: set[string]; 
			rec$uniq_mx=set_mx_uniq;
			local set_smtp_uniq: set[conn_id]; 
			rec$uniq_smtp=set_smtp_uniq;

			table_spam[src_ip]=rec;
			}

		# Update total mx queries
		++ table_spam[src_ip]$total_mx;

		# Update unique mx queries
		add table_spam[src_ip]$uniq_mx[query];

		if ( |table_spam[src_ip]$uniq_mx| > uniq_mx_threshold || table_spam[src_ip]$total_mx > total_mx_threshold )
			evaluate_spam( src_ip, table_spam );
		}
	}


event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	local src_ip = c$smtp$id$orig_h;

	# if this is the first time src_ip appears
	if (src_ip !in table_spam)
		{
		local rec: SpamRecord;
		rec$total_mx=0;
		local set_mx_uniq: set[string]; 
		rec$uniq_mx=set_mx_uniq;
		local set_smtp_uniq: set[conn_id]; 
		rec$uniq_smtp=set_smtp_uniq;

		table_spam[src_ip]=rec;
		}

	if(c$id !in table_spam[src_ip]$uniq_smtp)
			{
			add table_spam[src_ip]$uniq_smtp[c$id]; 
			if ( |table_spam[src_ip]$uniq_smtp| > total_smtp_threshold)
				evaluate_spam( src_ip, table_spam );
			}

	}
	


