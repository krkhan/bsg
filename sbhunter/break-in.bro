##! This script analyzes spam activity in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by setting a threshold on the total number
##! of mx queries made, unique mx queries and total number
##! of smtp queries. 

@load base/protocols/ssh
@load ./exploit

module Breakin;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		victim_ip:         addr             &log;
		attackers:         string           &log;		
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_breakin: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	const ssh_login_threshold = 1 &redef;
       }

global breakin_info:Breakin::Info;

event bro_init() &priority=5
	{
	Log::create_stream(Breakin::LOG, [$columns=Info, $ev=log_breakin]);
	}

## Type of the value of the global table table_spam
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here
type BreakinRecord: record {
    ssh_logins: count;
    ssh_attackers: set[addr];    		
};


function evaluate_breakin( dst_ip: addr, t: table[addr] of BreakinRecord  )
	{
	local s = t[dst_ip];
	if  ( s$ssh_logins > ssh_login_threshold )
		{
		local msg_attackers = "ssh:";
		for ( rec in s$ssh_attackers )
			msg_attackers = msg_attackers + fmt("%s,", rec);

		event Exploit::breakin( dst_ip, msg_attackers );

		## Log breakin-related entries
		breakin_info$ts = network_time();
		breakin_info$victim_ip = dst_ip;
		breakin_info$attackers = msg_attackers;

		Log::write(Breakin::LOG,breakin_info);

		delete t[dst_ip];
		}		
	}

## Called when an entry in the global table table_spam exceeds certain age, as specified
## in the table attribute create_expire.
function breakin_record_expired(t: table[addr] of BreakinRecord, idx: any): interval
	{
	evaluate_breakin(idx, t);
	return 0secs;
	}

# The global state table that maintains various information pertaining to the
## major event bot_attack, and is analyzed when a decision has to be made whether
## or not to declare the major event bot_attack.
global table_breakin: table[addr] of BreakinRecord &create_expire=2mins &expire_func=breakin_record_expired;	

event SSH::heuristic_failed_login(c: connection)
	{
	local id = c$id;
	local victim = id$resp_h;

	# if this is the first time src_ip appears
	if ( victim !in table_breakin )
		{
		local rec: BreakinRecord;
		rec$ssh_logins = 0;
		local set_ssh_attackers: set[addr]; 
		rec$ssh_attackers = set_ssh_attackers;

		table_breakin[victim]=rec;
		}

	++ table_breakin[victim]$ssh_logins;

	add table_breakin[victim]$ssh_attackers[id$orig_h];
	
	if ( table_breakin[victim]$ssh_logins > ssh_login_threshold )
		evaluate_breakin( victim, table_breakin );
	}

