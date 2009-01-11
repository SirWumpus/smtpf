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
	sub(/.*(snprintf|clamdError)\([^,]+, [^,]+, "/, "")
	sub(/"?\)( "\\r\\n.*| CRLF.*|, .*\);)$/, "")
	sub(/" ID_(MSG|NUM)\("?/, " #")
	sub(/(const char .*=|.*sess,) "/, "")
	sub(/" CLIENT_FORMAT "/, "%s [%s]")
	html_special();
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
