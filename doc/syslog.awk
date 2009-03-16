function html_special()
{
	gsub(/&/, "\\&amp;")
	gsub(/</, "\\&lt;")
	gsub(/>/, "\\&gt;")
	gsub(/\\"/, "\"")
}

/ReportLog/ {
	next
}
/LOG_(ERR|WARN|INFO).*LOG_(MSG|NUM)/ {
	sub(/"(, [^%\\].*|\);)$/, "")
	sub(/^[ 	syslog(]*LOG_/, "")
	sub(/.*const char .*= \/\* LOG_/, "")
	sub(/ *\*\//, ",");
	sub(/";/, "");
	sub(/, LOG_(MSG|NUM)\("?/, " #")
	sub(/"?\) "/, " ")
	sub(/" CLIENT_FORMAT "/, "%s [%s]")
	sub(/" _NAME "/, "@PACKAGE_NAME@")
	sub(/" _VERSION "/, "@PACKAGE_VERSION@")
	sub(/" _COPYRIGHT( "|\);)/, "@package_copyright@")
	html_special();
	if (match($0, /#[0-9]+/)) {
		msg_num = substr($0, RSTART, RLENGTH)
		printf("<a name='%s'></a>\n", msg_num)
	}
	print "<dt>", $0, "</dt>"
}
!dd_block && /\/\*{LOG/ {
	print "<dd>"
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
