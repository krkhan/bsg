@load base/protocols/dns

module DNSFail;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		# the source has generated a number of failed DNS queries
		DNSFail_Threshold_Reached,
	};

	type Info: record {
		orig_h:           addr          &log;
		failed_queries:   count         &log;
	};

	# If true, we consider only the DNS queries with rcode == 3 (Does Not Exist)
	# as failed queries
	const strict_rcode_checking = T &redef;

	# Threshold for reporting failed queries
	const failed_queries_trigger = 3 &redef;

	# Event handler for logging
	global log_dns_fail:
		event(rec: Info);
}

global failed_queries: table[addr] of count &default = 0;
global dns_fail_log: file;

function check_threshold(orig_h: addr): bool
	{
	if ( failed_queries[orig_h] % failed_queries_trigger == 0 )
		{
		local msg = fmt("%s has generated %d failed DNS queries",
			orig_h, failed_queries[orig_h]);

		NOTICE([$note=DNSFail_Threshold_Reached, $src=orig_h,
			$n=failed_queries[orig_h], $msg=msg]);
		}

	return F;
	}

event bro_init()
	{
	Log::create_stream(DNSFail::LOG, [$columns=Info, $ev=log_dns_fail]);
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
	for ( orig_h in failed_queries )
		{
			local rec: DNSFail::Info = [
				$orig_h=orig_h,
				$failed_queries=failed_queries[orig_h]
			];
			Log::write(DNSFail::LOG, rec);
		}
	}

