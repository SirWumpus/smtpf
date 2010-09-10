function smtp.connect (ip, ptr)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.connect hook: ip=".. ip ..",ptr=".. ptr)
	return 0
end

function smtp.helo (arg)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.helo hook: arg=".. arg)
	return 0
end

function smtp.mail (address, parray)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.mail hook: sender=".. address)
	return 0
end

function smtp.rcpt (address, parray)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.rcpt hook: rcpt=".. address)
	return 0
end

function smtp.data ()
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.data hook")
	return 0
end

function smtp.headers (headers)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.headers hook")
	return 0
end

function smtp.chunk (chunk, size)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.chunk hook")
	return 0
end

function smtp.dot (path)
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.dot hook: path=".. path)
	return 0
end

function smtp.rset ()
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.rset hook")
end

function smtp.close ()
	syslog.syslog(syslog.LOG_DEBUG, "lua smtp.close hook")
end
