module Blacklist_Mgr;

export {
	## table of blacklists. Each blacklist is a set of strings indexed
	## by a key. For example, the blacklist of CnC server ip addresses 
	## is indexed by the string "cnc_ip" and so forth. 
	const tb_blacklists: table[string] of set[string] &redef;

	## Name of the file that contains filenames of different blacklists
	## such as cnc_ip, cnc_url, spam_ip, bad_ip etc. The format of the file
	## is such that each line should represent a single file preceded by its
	## identifier. For example, cnc_ip ./cnc_ip.txt could be one line of the
	## file. The identifier used here (e.g. cnc_ip) is used to index
	## the filename in tb_blacklists too.
	const blacklist_srcfile="./files/try.txt" &redef;

	## The interval after which the blacklists must be refreshed, i.e., 
	## re-read from the blacklist files
	const blacklist_update_interval = 2mins &redef;	
}



## The event that refreshes our blacklists
global get_blacklists: event(srcfile: string);

## This event is called after each interval defined by 'blacklist_update_interval'.
## It takes as argument the name of the file which contains filenames of blacklists.
## It then updates blacklists from corresponding files.
event get_blacklists(srcfile: string)
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
		local file_name = arr[2];

		local s = read_file(file_name);
		tb_blacklists[file_id]=s;
		}
	print tb_blacklists;
	schedule blacklist_update_interval { Blacklist_Mgr::get_blacklists(blacklist_srcfile) };	
	}

event bro_init()
	{
	event Blacklist_Mgr::get_blacklists(blacklist_srcfile);
	}



