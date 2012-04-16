module spam;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		total_mx:          count            &log;
		uniq_mx:           count            &log;
		entropy_mx:        double           &log;
		total_smtp:	   count 	    &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_spam: event(rec: Info);

	## Thresholds
	const uniq_mx_threshold = 0 &redef;
	const total_mx_threshold = 0 &redef;
	const entropy_mx_threshold = 0 &redef;
	const total_smtp_threshold = 0 &redef;
       }

global num_req: count;
global num_rep: count;

event bro_init()
{
	num_req=0;
	num_rep=0;
}

global spam_info:spam::Info;


event bro_init() &priority=5
	{
	Log::create_stream(spam::LOG, [$columns=Info, $ev=log_spam]);
	}


type SpamRecord: record {
    uniq_mx:set[string] &optional;
    total_mx:count;
    entropy_mx:double;
    total_smtp:count;	
};

function spam_record_expired(t: table[string] of SpamRecord, idx: any): interval
	{

	local result: entropy_test_result;
	result = entropy_test_finish(idx);
	t[idx]$entropy_mx = result$entropy;

	## Log spam-related entries

	spam_info$ts= network_time();
	spam_info$uniq_mx= |t[idx]$uniq_mx|;
	spam_info$total_mx=t[idx]$total_mx;
	spam_info$entropy_mx=t[idx]$entropy_mx;
	spam_info$total_smtp=t[idx]$total_smtp;

	Log::write(spam::LOG,spam_info);

	return 0secs;
	}


global table_spam: table[addr] of SpamRecord &create_expire=15mins &expire_func=spam_record_expired;


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	
	if(c$dns$qtype_name=="MX")
		{
		local src_ip = c$dns$id$orig_h;
		# if this is the first time src_ip is sending mx query, initialize the incremental entropy for it
		if (src_ip !in table_spam)
			{
			local rec: SpamRecord;
			rec$entropy_mx=0.0;
			rec$total_mx=0;
			rec$total_smtp=0;
			local set_uniq: set[string]; 
			rec$uniq_mx=set_uniq;

			table_spam[src_ip]=rec;
			
			local done:bool;
			done = entropy_test_init(src_ip);
			}

		# Update total mx queries
		++ table_spam[src_ip]$total_mx;

		# Add the query to incremental entropy calculation 
		done = entropy_test_add(src_ip, query);
		

		# Update unique mx queries
		add table_spam[src_ip]$uniq_mx[query];

		}

	}

global uniq_smtp: set[conn_id];

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{

	local src_ip = c$smtp$id$orig_h;
	if(c$id !in uniq_smtp)
	{
		add uniq_smtp[c$id]; 
		print c$smtp;
		print "\n \n";
		print "------------------------------------------------------------------";
		++ num_req;
	}


	# if this is the first time src_ip appears
	if (src_ip !in table_spam)
		{
		local rec: SpamRecord;
		rec$entropy_mx=0.0;
		rec$total_mx=0;
		rec$total_smtp=0;
		local set_uniq: set[string]; 
		rec$uniq_mx=set_uniq;

		table_spam[src_ip]=rec;
			
		local done:bool;
		done = entropy_test_init(src_ip);
		}

		# Update total mx queries
		++ table_spam[src_ip]$total_smtp;

	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
	{
		++ num_rep;
	}

event bro_done()
	{
		print "Total requests: ";
		print num_req;
			print "Total replies: ";
		print num_rep;
		print "Unique ids";
		print |uniq_smtp|;
	}
	


