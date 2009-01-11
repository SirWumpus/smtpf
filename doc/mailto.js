//
// mailto.js
//
// Original idea from http://innerpeace.org/escrambler.shtml
//
// Scramble your email address from SPAM Email Crawlers.
//
//
// Add the following to the <head> section of a HTML page:
//
//	<script language="JavaScript1.1" src="/Lib/mailto.js"></script>
//
// For every place you use the URL "mailto:user@my.domain.tld",
// replace the URL with:
//
//	javascript:mailto()
//
// To support multiple email addresses, just copy/paste the function
// below once for each address, rename the function, and specify the
// account name and host name variables.
//
// The scrambling comes two fold: first, the JavaScript is in a
// separate file which probably won't be fetched; second, the email
// is address broken up into pieces.
//
// Works in IE 4, 5, 6 and Netscape 4.7, 6.
//

function mailto(here)
{
	here = here.replace(/\s+at\s+/, '@');
	here = here.replace(/\s+dot\s+/g, '.');
	location.href = "mailto:" + here;
}

function achowe()
{
	mailto('achowe at snert dot com');
}

function sales()
{
	mailto('sales at snertsoft dot com');
}

function fsl()
{
	mailto('info at fsl dot com');
}

function milters()
{
	mailto('milters at milter dot info');
}

function miltersRequest(subject)
{
	var account = "milters-request";
	var host = "milter.info";
	location.href = "mailto:" + account + "@" + host + "?subject=" + subject;
}

function barricademx()
{
	mailto('milters at milter dot info');
}

function barricademxRequest(subject)
{
	var account = "barricademx-request";
	var host = "snertsoft.info";
	location.href = "mailto:" + account + "@" + host + "?subject=" + subject;
}

