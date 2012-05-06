##! This script analyzes spam activity in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by setting a threshold on the total number
##! of mx queries made, unique mx queries and total number
##! of smtp queries. 

@load botflex/utils/types
@load botflex/config

module Spam;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:		   addr		    &log;
		mx_queries:        count            &log;
		smtp_conns:	   count 	    &log;
		msg:               string           &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## The contributory factors (or tributaries) to major event spam
	type spam_tributary: enum { SMTP_threshold_crossed, MX_query_threshold_crossed };

	## Expire interval for the global table concerned with maintaining cnc info
	const wnd_spam = 2mins &redef;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	const spam_evaluation_mode = OR;

	## The event that spam.bro reports spam
	global spam: event( ts: time, src_ip: addr, msg: string );

	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_spam: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	const mx_threshold = 1 &redef;
	const smtp_threshold = 1 &redef;
       }

global spam_info:Spam::Info;

event bro_init()
	{
	Log::create_stream(Spam::LOG, [$columns=Info, $ev=log_spam]);
	if ( "spam" in Config::table_config  )
			{
			if ( "th_smtp" in Config::table_config["spam"] )
				{
				smtp_threshold = to_count(Config::table_config["spam"]["th_smtp"]);
				}
			if ( "th_mx" in Config::table_config["spam"] )
				{
				mx_threshold = to_count(Config::table_config["spam"]["th_mx"]);
				}
			if ( "wnd_spam" in Config::table_config["spam"] )
				{
				wnd_spam = string_to_interval(Config::table_config["spam"]["wnd_spam"]);
				}
			if ( "evaluation_mode" in Config::table_config["spam"] )
				{
				spam_evaluation_mode = string_to_evaluationmode(Config::table_config["spam"]["evaluation_mode"]);
				}
			}
	
	}

## Type of the value of the global table table_spam
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here
type SpamRecord: record {
    tb_tributary: table[ spam_tributary ] of bool;
    n_mx_queries: count &default=0;
    # Within an smtp connection, several messages fly back and forth between
    # the source and destination. We need only the number of unique smtp 
    # connections initiated by an internal host 	
    uniq_smtp: set[conn_id];	
};

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[spam_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[spam_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[spam_tributary] of bool ): bool
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

## The function that decides whether or not the major event spam should
## be generated. It is called (i) every time an entry in the global table table_spam
## reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 
function evaluate( src_ip: addr, t: table[addr] of SpamRecord  ): bool
	{
	local do_report: bool;
	if ( spam_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( spam_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( spam_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{
		local msg = "";
		if ( t[src_ip]$tb_tributary[ SMTP_threshold_crossed ] )
			msg = msg + "Large number of SMTP connections initiated;";
		if ( t[src_ip]$tb_tributary[ MX_query_threshold_crossed ] )
			msg = msg + "Large number of MX queries made;";

		event Spam::spam( network_time(), src_ip, msg );

		## Log spam-related entries
		spam_info$ts = network_time();
		spam_info$src_ip = src_ip;
		spam_info$mx_queries = |t[src_ip]$n_mx_queries|;
		spam_info$smtp_conns = |t[src_ip]$uniq_smtp|;
		spam_info$msg = msg;

		Log::write(Spam::LOG,spam_info);

		return T;
		}	
	return F;	
	}

## Called when an entry in the global table table_spam exceeds certain age, as specified
## in the table attribute create_expire.
function spam_record_expired(t: table[addr] of SpamRecord, idx: any): interval
	{
	evaluate(idx, t);
	return 0secs;
	}

# The global state table that maintains various information pertaining to the
## major event bot_attack, and is analyzed when a decision has to be made whether
## or not to declare the major event bot_attack.
global table_spam: table[addr] of SpamRecord &create_expire=wnd_spam &expire_func=spam_record_expired;	


function get_spam_record(): SpamRecord
	{
	local rec: SpamRecord;
	local set_smtp_uniq: set[conn_id]; 
	rec$uniq_smtp = set_smtp_uniq;

	return rec;
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{	
	if(c$dns$qtype_name == "MX")
		{
		local src_ip = c$dns$id$orig_h;
		local outbound = Site::is_local_addr(src_ip);
		
		if ( outbound )
			{ 
			if (src_ip !in table_spam)
				table_spam[src_ip] = get_spam_record();

			# Update total mx queries
			++ table_spam[src_ip]$n_mx_queries;

			if ( table_spam[src_ip]$n_mx_queries > mx_threshold )
				{
				table_spam[src_ip]$tb_tributary[ MX_query_threshold_crossed ]=T;
				local done = evaluate( src_ip, table_spam );

				## Reset mx parameters
				if (done)
					{
					delete table_spam[src_ip]$tb_tributary[ MX_query_threshold_crossed ];
					table_spam[src_ip]$n_mx_queries=0;
					}	
				}	
			}
		}
	}


event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	local src_ip = c$smtp$id$orig_h;

	local outbound = Site::is_local_addr(src_ip);
		
	if ( outbound )
		{ 
		# if this is the first time src_ip appears
		if (src_ip !in table_spam)
			table_spam[src_ip] = get_spam_record();

		if(c$id !in table_spam[src_ip]$uniq_smtp)
				{
				add table_spam[src_ip]$uniq_smtp[c$id]; 
				if ( |table_spam[src_ip]$uniq_smtp| > smtp_threshold)
					{
					table_spam[src_ip]$tb_tributary[ SMTP_threshold_crossed ]=T;
					local done = evaluate( src_ip, table_spam );

					## Reset smtp parameters
					if (done)
						{
						delete table_spam[src_ip]$tb_tributary[ SMTP_threshold_crossed ];
						for ( rec in table_spam[src_ip]$uniq_smtp )
							delete table_spam[src_ip]$uniq_smtp[rec];
						}	
					}
				}
		}

	}
	


