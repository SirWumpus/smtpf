handle SIG32 nostop noprint pass
handle SIG33 nostop noprint pass
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIGPIPE nostop pass
handle SIGTERM nostop pass
handle SIGQUIT nostop pass
set listsize 20
b uribl_test_uri_cb
b mailbl_test_uri_cb
b uriCheckString
b uriblData
#b uriblPtrConnect
#b uriblHeloMail
#b uriblMailMail
