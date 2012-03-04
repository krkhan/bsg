# example cnc server list

signature cnc-blacklist {
	ip-proto == tcp
	dst-ip ==
		143.215.130.33,
		209.85.153.100
	event "cnc contacted"
}

