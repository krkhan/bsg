##! Manages our blacklists

module BlacklistMgr;

export {
	## table of blacklists. Each blacklist is a set of strings indexed
	## by a key. For example, the blacklist of CnC server ip addresses 
	## is indexed by the string "cnc_ip" and so forth. 
	const tb_blacklists: table[string] of set[string] &redef;

	## blacklist for subnets. A subnet cannot be treated as a string as it
	## represents an entire range of ip addresses and must be treated as such.
	## What we are going with for now is to read in the subnet file in tb_blacklists 
	## as strings and then parse it again and convert it to a set of subnets, and delete 
	## the corresponding entry in tb_blacklists (where subnets were strings) 
	const blacklist_rbn_subnet: set[subnet] &redef; 

	## Blacklist of most exploited / vulnerable ports
	const blacklist_bad_ports: set[port] &redef; 

	## Name of the file that contains filenames of different blacklists
	## such as cnc_ip, cnc_url, spam_ip, bad_ip etc. The format of the file
	## is such that each line should represent a single file preceded by its
	## identifier. For example, cnc_ip ./cnc_ip.txt could be one line of the
	## file. The identifier used here (e.g. cnc_ip) is used to index
	## the filename in tb_blacklists too.
	global blacklist_srcfile="/usr/local/bro/share/bro/site/botflex/services/src_blacklists.txt" &redef;

	## The interval after which the blacklists must be refreshed, i.e., 
	## re-read from the blacklist files
	const blacklist_update_interval = 24hrs &redef;

	## The prefix for blacklist files.The file blacklist_srcfile contains
	## only filenames, such as cnc_url.txt etc. The actual path where this
	## file will be found is specified by the variable below.
	global prefix_blacklist = "/usr/local/bro/share/bro/site/botflex/blacklists/" &redef;	
}



## The event that refreshes our blacklists
global get_blacklists: event(srcfile: string);

## This event is called after each interval defined by 'blacklist_update_interval'.
## It takes as argument the name of the file which contains filenames of blacklists.
## It then updates blacklists from corresponding files.
event get_blacklists(srcfile: string) &priority=30
	{
	for( rec in tb_blacklists )
		{
		delete tb_blacklists[rec];
		}
	local blacklist_srcfiles = read_file(srcfile);

	for( f in blacklist_srcfiles )
		{ 
		local arr = split( f, /[[:blank:]]*/ );
		local file_id = arr[1];
		local file_name = prefix_blacklist+arr[2];
		tb_blacklists[file_id]=read_file(file_name);

		## If it is a blacklist comprising subnets, place it in a separate list
		## meant for holding subnets and not subnets represented as strings.
		if ( file_id == "rbn_subnet" )
			{
			for ( str_subnet in tb_blacklists[file_id] )
				add blacklist_rbn_subnet[ to_subnet(str_subnet) ];

			# delete the redundant string version of the subnet list from tb_blacklists
			delete tb_blacklists[file_id];
			}
		## If it is a blacklist comprising ports, place it in a separate list
		## meant for holding ports and not ports represented as strings.
		if ( file_id == "bad_ports" )
			{
			for ( str_port in tb_blacklists[file_id] )
				add blacklist_bad_ports[ to_port(str_port+"/tcp") ];

			# delete the redundant string version of the ports list from tb_blacklists
			delete tb_blacklists[file_id];
			}
		
		}
	schedule blacklist_update_interval { BlacklistMgr::get_blacklists(blacklist_srcfile) };	
	}

event bro_init() &priority=25
	{
	event BlacklistMgr::get_blacklists(blacklist_srcfile);
	}



