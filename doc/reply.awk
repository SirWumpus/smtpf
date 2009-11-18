function html_special()
{
	gsub(/&/, "\\&amp;")
	gsub(/</, "\\&lt;")
	gsub(/>/, "\\&gt;")
	gsub(/\\"/, "\"")
}

/ID_(MSG|NUM)/ {
	sub(/.*reply.*\([^"]+, "/, "")
	sub(/.*(SENDCLIENT|sendClientReply)\([^,]+, "/, "")
	sub(/.*(snprintf|clamdError|ctasdError)\([^,]+, [^,]+, "/, "")
	sub(/"?\)( "\\r\\n.*| CRLF.*|, .*\);)$/, "")
	sub(/" ID_(MSG|NUM)\("?/, " #")
	sub(/(const char .*=|.*sess,) "/, "")
	sub(/" CLIENT_FORMAT "/, "%s [%s]")
	html_special();
	if (match($0, /#[0-9]+/)) {
		msg_num = substr($0, RSTART+1, RLENGTH-1)
		printf("<a name='%s'></a>\n", msg_num)
	}
	print "<dt class=\"message\">", $0, "</dt>"
}
!dd_block && /\/\*{REPLY/ {
	print "<dd class=\"message\">"
	dd_block = 1
	next
}
dd_block && /}\*\//{
	print "</dd>"
	dd_block = 0
	next
}
dd_block {
# Should already be in HTML.
#	html_special();
	print
}
