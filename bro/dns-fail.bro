@load dns

module DNSFail;

export {
	redef enum Notice += {
		DNSFailThreshold,	# the source has generated a number of failed DNS queries
	};

	# If true, we consider only the DNS queries with rcode == 3 (Does Not Exist)
	# as failed queries
	const strict_rcode_checking = T &redef;

	# Threshold for reporting failed queries
	const failed_queries_trigger = 100 &redef;

	# Set to false to disable printing to dns-fail.log
	const logging = T &redef;

	global check_threshold:
		function(orig_h: addr): bool;
}

global failed_queries: table[addr] of count &default = 0;
global dns_fail_log: file;

function check_threshold(orig_h: addr): bool
	{
		if ( failed_queries[orig_h] % failed_queries_trigger == 0 )
			{
			local msg = fmt("%s has generated %d failed DNS queries",
				orig_h, failed_queries[orig_h]);
			print msg;
			if ( logging )
				print dns_fail_log, msg;
			}

		return F;
	}

event bro_init()
	{
	if ( logging )
		dns_fail_log = open_log_file("dns-fail");
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local id = c$id;
	if ( (strict_rcode_checking && msg$rcode == 3) || msg$rcode != 0 )
		{
		failed_queries[id$orig_h] = failed_queries[id$orig_h] + 1;
		check_threshold(id$orig_h);
		}
	}

event bro_done()
	{
	if ( logging )
		{
			print dns_fail_log, "Summary:"
			for ( orig_h in failed_queries )
				{
					print dns_fail_log, fmt("%s %d", orig_h, failed_queries[orig_h]);
				}
		}
	}

