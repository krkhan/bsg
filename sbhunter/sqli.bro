##! This script analyzes sql injection attack in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by looking for sql injection related signature
##! in uri's in http requests. It is based on the original detect-sqli.bro in 
##! /policy/protocols/http.

@load ./bot-attack

module Sqli;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip: 	   addr		    &log;
		sqli_attempts:     count            &log;
		sqli_victims:	   string	    &log;
			
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_sqli: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	const sqli_attempt_threshold = 1 &redef;

	## Regular expression is used to match URI based SQL injections.
	const match_sql_injection_uri = 
		  /[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// &redef;
       }

global sqli_info:Sqli::Info;

event bro_init() &priority=5
	{
	Log::create_stream(Sqli::LOG, [$columns=Info, $ev=log_sqli]);
	}

## Type of the value of the global table table_sqli
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here
type SqliRecord: record {
    sqli_attempts: count;
    sqli_victims: set[addr];
};

 
function evaluate_sqli( src_ip: addr, t: table[addr] of SqliRecord  )
	{
	local s = t[src_ip];
	if  ( s$sqli_attempts > sqli_attempt_threshold )
		{
		local victims = "";
		for (rec in s$sqli_victims)
			victims = victims + fmt("%s,",rec); 

		event Bot_Attack::sqli( src_ip, victims );

		## Log spam-related entries
		sqli_info$ts = network_time();
		sqli_info$sqli_attempts = s$sqli_attempts;
		sqli_info$sqli_victims = victims;

		Log::write(Sqli::LOG,sqli_info);

		delete t[src_ip];
		}		
	}

## Called when an entry in the global table table_sqli exceeds certain age, as specified
## in the table attribute create_expire.
function sqli_record_expired(t: table[addr] of SqliRecord, idx: any): interval
	{
	evaluate_sqli(idx, t);
	return 0secs;
	}

# The global state table that maintains various information pertaining to the
## major event bot_attack, and is analyzed when a decision has to be made whether
## or not to declare the major event bot_attack.
global table_sqli: table[addr] of SqliRecord &create_expire=2mins &expire_func=sqli_record_expired;	

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
	{
	if ( match_sql_injection_uri in unescaped_URI )
		{
		local src_ip = c$http$id$orig_h;

		if (src_ip !in table_sqli)
			{
			local rec: SqliRecord;
			rec$sqli_attempts = 0;
			local set_sqli_victims: set[addr]; 
			rec$sqli_victims = set_sqli_victims;

			table_sqli[src_ip] = rec;
			}

		# Update total mx queries
		++ table_sqli[src_ip]$sqli_attempts;

		add table_sqli[src_ip]$sqli_victims[c$http$id$resp_h];

		if ( table_sqli[src_ip]$sqli_attempts > sqli_attempt_threshold )
			evaluate_sqli( src_ip, table_sqli );
		}
	}

	


