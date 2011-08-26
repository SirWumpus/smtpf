/*
 * lua.c
 *
 * Copyright 2010 by Anthony Howe. All rights reserved.
 */

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_LUA

#include "smtpf.h"

#include <ctype.h>

#include <com/snert/lib/io/Log.h>

/***********************************************************************
 ***
 ***********************************************************************/

Verbose verb_lua	= { { "lua", "-", "" } };

Stats stat_lua_connect	= { STATS_TABLE_CONNECT, "lua-connect" };
Stats stat_lua_helo	= { STATS_TABLE_CONNECT, "lua-helo" };
Stats stat_lua_mail	= { STATS_TABLE_MAIL, "lua-mail" };
Stats stat_lua_rcpt	= { STATS_TABLE_RCPT, "lua-rcpt" };
Stats stat_lua_data	= { STATS_TABLE_DATA, "lua-data" };
Stats stat_lua_headers	= { STATS_TABLE_MSG, "lua-headers" };
Stats stat_lua_content	= { STATS_TABLE_MSG, "lua-content" };
Stats stat_lua_dot	= { STATS_TABLE_MSG, "lua-dot" };

FilterContext lua_context;

/***********************************************************************
 ***
 ***********************************************************************/

static void
lua_table_set_integer(lua_State *L, int table_index, const char *name, lua_Integer value)
{
	lua_pushinteger(L, value);
	lua_setfield(L, table_index - (table_index < 0), name);
}

static void
lua_table_set_string(lua_State *L, int table_index, const char *name, const char *value)
{
	lua_pushstring(L, value);
	lua_setfield(L, table_index - (table_index < 0), name);
}

struct map_integer {
	const char *name;
	lua_Integer value;
};

static struct map_integer syslog_constants[] = {
	{ "LOG_EMERG", 		LOG_EMERG },
	{ "LOG_ALERT", 		LOG_ALERT },
	{ "LOG_CRIT", 		LOG_CRIT },
	{ "LOG_ERR", 		LOG_ERR },
	{ "LOG_WARNING", 	LOG_WARNING },
	{ "LOG_NOTICE", 	LOG_NOTICE },
	{ "LOG_INFO", 		LOG_INFO },
	{ "LOG_DEBUG", 		LOG_DEBUG },

	{ "LOG_KERN", 		LOG_KERN },
	{ "LOG_USER", 		LOG_USER },
	{ "LOG_MAIL", 		LOG_MAIL },
	{ "LOG_DAEMON", 	LOG_DAEMON },
	{ "LOG_AUTH", 		LOG_AUTH },
	{ "LOG_SYSLOG", 	LOG_SYSLOG },
	{ "LOG_LPR", 		LOG_LPR },
	{ "LOG_NEWS", 		LOG_NEWS },
	{ "LOG_UUCP", 		LOG_UUCP },
	{ "LOG_CRON", 		LOG_CRON },
	{ "LOG_AUTHPRIV", 	LOG_AUTHPRIV },
	{ "LOG_FTP", 		LOG_FTP },
	{ "LOG_LOCAL0", 	LOG_LOCAL0 },
	{ "LOG_LOCAL1", 	LOG_LOCAL1 },
	{ "LOG_LOCAL2", 	LOG_LOCAL2 },
	{ "LOG_LOCAL3", 	LOG_LOCAL3 },
	{ "LOG_LOCAL4", 	LOG_LOCAL4 },
	{ "LOG_LOCAL5", 	LOG_LOCAL5 },
	{ "LOG_LOCAL6", 	LOG_LOCAL6 },
	{ "LOG_LOCAL7", 	LOG_LOCAL7 },

	{ "LOG_PID", 		LOG_PID },
	{ "LOG_CONS", 		LOG_CONS },
	{ "LOG_ODELAY", 	LOG_ODELAY },
	{ "LOG_NDELAY", 	LOG_NDELAY },
	{ "LOG_NOWAIT", 	LOG_NOWAIT },
	{ "LOG_PERROR", 	LOG_PERROR },

	{ NULL, 0 }
};

/**
 * syslog.openlog(string, syslog.LOG_PID or syslog.LOG_NDELAY, syslog.LOG_USER);
 */
static int
lua_openlog(lua_State *L)
{
	int options = luaL_optint(L, 2, LOG_PID);
	int facility = luaL_optint(L, 3, LOG_USER);
	const char *ident = luaL_checkstring(L, 1);

	openlog(ident, options, facility);

	return 0;
}

/**
 * syslog.syslog(syslog.LOG_INFO, string);
 */
static int
lua_syslog(lua_State *L)
{
	int level;
	const char *sess_id;

	lua_getglobal(L, "smtp");	/* level msg -- level msg smtp */
	lua_getfield(L, -1, "sess");	/* level msg smtp -- level msg smtp sess */
	lua_getfield(L, -1, "id");	/* level msg smtp sess -- level msg smtp sess id */
	sess_id = lua_tostring(L, -1);
	level = luaL_optint(L, 1, LOG_DEBUG);

	syslog(level, "%s " LOG_NUM(000) "lua: %s", sess_id, luaL_checkstring(L, 2));

	lua_pop(L, 3);			/* level msg smtp sess id -- level msg */

	return 0;
}

/**
 * syslog.error(message);
 *
 * This function can be used for lua_pcall() errfunc.
 */
static int
lua_log_error(lua_State *L)
{
	lua_pushinteger(L, LOG_ERR);	/* msg -- msg LOG_ERR */
	lua_insert(L, -2);		/* msg LOG_ERR -- LOG_ERR msg */

	return lua_syslog(L);
}

/**
 * syslog.info(message);
 *
 * This function can be used for lua_pcall() errfunc.
 */
static int
lua_log_info(lua_State *L)
{
	lua_pushinteger(L, LOG_INFO);	/* msg -- msg LOG_INFO */
	lua_insert(L, -2);		/* msg LOG_INFO -- LOG_INFO msg */

	return lua_syslog(L);
}

/**
 * syslog.debug(message);
 *
 * This function can be used for lua_pcall() errfunc.
 */
static int
lua_log_debug(lua_State *L)
{
	lua_pushinteger(L, LOG_DEBUG);	/* msg -- msg LOG_DEBUG */
	lua_insert(L, -2);		/* msg LOG_DEBUG -- LOG_DEBUG msg */

	return lua_syslog(L);
}

/**
 * syslog.closelog();
 */
static int
lua_closelog(lua_State *L)
{
	closelog();

	return 0;
}

static void
lua_define_syslog(lua_State *L)
{
	struct map_integer *map;

	lua_newtable(L);

	for (map = syslog_constants; map->name != NULL; map++) {
		lua_table_set_integer(L, -1, map->name, map->value);
	}

	lua_pushcfunction(L, lua_openlog);
	lua_setfield(L, -2, "openlog");
	lua_pushcfunction(L, lua_syslog);
	lua_setfield(L, -2, "syslog");
	lua_pushcfunction(L, lua_closelog);
	lua_setfield(L, -2, "closelog");
	lua_pushcfunction(L, lua_log_error);
	lua_setfield(L, -2, "error");
	lua_pushcfunction(L, lua_log_info);
	lua_setfield(L, -2, "info");
	lua_pushcfunction(L, lua_log_debug);
	lua_setfield(L, -2, "debug");

	lua_setglobal(L, "syslog");
}

static void
lua_define_smtp(lua_State *L, Session *sess)
{
	lua_newtable(L);		/* -- smtp */

	/* Build smtp.code. */
	lua_newtable(L);		/* smtp -- smtp code */
	lua_table_set_integer(L, -1, "ok", 250);
	lua_table_set_integer(L, -1, "closing", 421);
	lua_table_set_integer(L, -1, "busy", 450);
	lua_table_set_integer(L, -1, "again", 451);
	lua_table_set_integer(L, -1, "storage", 452);
	lua_table_set_integer(L, -1, "bad_syntax", 500);
	lua_table_set_integer(L, -1, "bad_arg", 501);
	lua_table_set_integer(L, -1, "bad_command", 502);
	lua_table_set_integer(L, -1, "bad_sequence", 503);
	lua_table_set_integer(L, -1, "bad_param", 504);
	lua_table_set_integer(L, -1, "reject", 550);
	lua_table_set_integer(L, -1, "bad_user", 551);
	lua_table_set_integer(L, -1, "over_quota", 552);
	lua_table_set_integer(L, -1, "bad_address", 553);
	lua_table_set_integer(L, -1, "failed", 554);
	lua_setfield(L, -2, "code");	/* smtp code -- smtp */

	/* Build smtp.sess. */
	lua_newtable(L);		/* smtp -- smtp sess */
	lua_table_set_string(L, -1, "id", sess->session->id_log);
	lua_table_set_string(L, -1, "ip", sess->client.addr);
	lua_table_set_string(L, -1, "ptr", sess->client.name);
	lua_setfield(L, -2, "sess");	/* smtp sess -- smtp */

	/* Build smtp.tran. */
	lua_newtable(L);		/* smtp -- smtp trans */
	lua_pushnil(L);
	lua_setfield(L, -2, "id");
	lua_setfield(L, -2, "trans");	/* smtp trans -- smtp */

	/* Define smtp global. */
	lua_setglobal(L, "smtp");	/* smtp -- */
}

static SmtpfCode
lua_result(Session *sess, lua_State *L, const char *func_name, Stats *stat)
{
	SmtpfCode rc = SMTPF_CONTINUE;
	lua_Integer smtp_code = lua_tointeger(L, -2);
	const char *smtp_reply = lua_tostring(L, -1);

	if (verb_lua.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "lua %s smtp-code=%ld smtp-reply=\"%s\"", LOG_ARGS(sess), func_name, (long) smtp_code, TextNull(smtp_reply));

	if (smtp_code != 0 && smtp_code != SMTP_OK) {
		rc = replyPushFmt(sess, smtp_code / 100, "%d %d.0.0 %s" ID_MSG(000) CRLF, smtp_code, smtp_code / 100, smtp_reply, ID_ARG(sess));
		statsCount(stat);
	}

	lua_pop(L, 3);		/* smtp code reply -- */

	return rc;
}

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef NOT_USED
SmtpfCode
luaInit(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

SmtpfCode
luaFini(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}

SmtpfCode
luaOptn(Session *null, va_list ignore)
{
	return SMTPF_CONTINUE;
}
#endif

SmtpfCode
luaRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_lua);

	(void) statsRegister(&stat_lua_connect);
	(void) statsRegister(&stat_lua_helo);
	(void) statsRegister(&stat_lua_mail);
	(void) statsRegister(&stat_lua_rcpt);
	(void) statsRegister(&stat_lua_data);
	(void) statsRegister(&stat_lua_headers);
	(void) statsRegister(&stat_lua_content);
	(void) statsRegister(&stat_lua_dot);

	lua_context = filterRegisterContext(sizeof (LuaContext));

	return SMTPF_CONTINUE;
}

SmtpfCode
luaConnect0(Session *sess, va_list args)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaConnect0);

	if ((ctx->lua = luaL_newstate()) == NULL)
		goto error0;

	/* Setup session notes, id, constants. */
	lua_define_syslog(ctx->lua);
	lua_define_smtp(ctx->lua, sess);

	lua_getglobal(ctx->lua, "syslog");	/* -- syslog */
	lua_getfield(ctx->lua, -1, "error");	/* syslog -- syslog error */
	lua_remove(ctx->lua, -2);		/* syslog error -- error */

	switch (luaL_loadfile(ctx->lua, LUA_FILE)) {	/* error -- error file */
	case LUA_ERRFILE:
		if (!verb_lua.option.value)
			goto error1;
		/*@fallthrough@*/

	case LUA_ERRMEM:
	case LUA_ERRSYNTAX:
		syslog(LOG_ERR, LOG_MSG(000) "lua load: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		goto error1;
	}

	/* Stop collector during initialization. */
	lua_gc(ctx->lua, LUA_GCSTOP, 0);
	luaL_openlibs(ctx->lua);
	lua_gc(ctx->lua, LUA_GCRESTART, 0);

	if (verb_lua.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "luaConnect0 top before=%d", LOG_ARGS(sess), lua_gettop(ctx->lua));

	if (lua_pcall(ctx->lua, 0, LUA_MULTRET, -2)) {
		goto error1;
	}

	if (verb_lua.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "luaConnect0 top after=%d", LOG_ARGS(sess), lua_gettop(ctx->lua));

	return SMTPF_CONTINUE;
error1:
	lua_close(ctx->lua);
	ctx->lua = NULL;
error0:
	return SMTPF_CONTINUE;
}

SmtpfCode
luaConnect1(Session *sess, va_list args)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaConnect1);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_connect(ip, ptr)
	 * 	Return 0 (continue) on success or SMTP code and SMTP reply.
	 */
	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "connect");	/* smtp -- smtp connect */
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);		/* smtp connect -- */
		return SMTPF_CONTINUE;
	}

	lua_pushstring(ctx->lua, sess->client.addr);	/* smtp connect -- smtp connect ip */
	lua_pushstring(ctx->lua, sess->client.name);	/* smtp connect ip -- smtp connect ip ptr */

	if (verb_lua.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "luaConnect1 top before=%d", LOG_ARGS(sess), lua_gettop(ctx->lua));

	if (lua_pcall(ctx->lua, 2, 2, 0)) {	/* smtp connect ip ptr -- smtp code reply */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.connect: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	if (verb_lua.option.value)
		syslog(LOG_DEBUG, LOG_MSG(000) "luaConnect1 top after=%d", LOG_ARGS(sess), lua_gettop(ctx->lua));

	return lua_result(sess, ctx->lua, "smtp.connect", &stat_lua_connect);
}

SmtpfCode
luaHelo(Session *sess, va_list args)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);
	const char *helo = va_arg(args, const char *);

	LOG_TRACE(sess, 000, luaHelo);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "sess");
	lua_table_set_string(ctx->lua, -1, "helo", helo);
	lua_pop(ctx->lua, 1);			/* smtp sess -- smtp */

	/* smtp_code, smtp_reply = smtp_helo(helo_arg)
	 * 	Return 250 on success or SMTP code and SMTP reply.
	 */
	lua_getfield(ctx->lua, -1, "helo");	/* smtp -- smtp helo */
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);		/* smtp helo -- */
		return SMTPF_CONTINUE;
	}

	lua_pushstring(ctx->lua, helo);

	if (lua_pcall(ctx->lua, 1, 2, 0)) {	/* smtp helo helo_arg -- smtp code reply */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.helo: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	return lua_result(sess, ctx->lua, "smtp.helo", &stat_lua_helo);
}

SmtpfCode
luaMail(Session *sess, va_list args)
{
	int i;
	char **param;
	ParsePath *mail = va_arg(args, ParsePath *);
	Vector params_list = va_arg(args, Vector);
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaMail);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "trans");	/* smtp -- smtp trans */
	lua_table_set_string(ctx->lua, -1, "id", sess->msg.id);
	lua_table_set_string(ctx->lua, -1, "sender", mail->address.string);
	lua_pop(ctx->lua, 1);			/* smtp trans -- smtp */

	/* smtp_code, smtp_reply = smtp_mail(sender, parameters)
	 * 	Return 250 on success or SMTP code and SMTP reply.
	 */
	lua_getfield(ctx->lua, -1, "mail");	/* smtp trans -- smtp mail */
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);		/* smtp mail -- */
		return SMTPF_CONTINUE;
	}

	lua_pushstring(ctx->lua, mail->address.string);	/* smtp mail -- smtp mail addr */
	lua_createtable(ctx->lua, VectorLength(params_list), 0);	/* smtp mail addr -- smtp mail addr array */
	for (i = 0, param = (char **) VectorBase(params_list); *param != NULL; param++, i++) {
		lua_pushstring(ctx->lua, *param);	/* smtp mail addr array -- smtp mail addr array value */
		lua_rawseti(ctx->lua, -2, i);		/* smtp mail addr array value -- smtp mail addr array */
	}

	if (lua_pcall(ctx->lua, 2, 2, 0)) {	/* smtp mail addr array -- smtp code reply */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.mail: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	return lua_result(sess, ctx->lua, "smtp.mail", &stat_lua_mail);
}


SmtpfCode
luaRcpt(Session *sess, va_list args)
{
	int i;
	char **param;
	ParsePath *rcpt = va_arg(args, ParsePath *);
	Vector params_list = va_arg(args, Vector);
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaRcpt);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_rcpt(recipient, parameter_list)
	 * 	Return 250 on success or SMTP code and SMTP reply.
	 */
	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "rcpt");	/* smtp -- smtp rcpt */
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);		/* smtp rcpt -- */
		return SMTPF_CONTINUE;
	}

	lua_pushstring(ctx->lua, rcpt->address.string);	/* smtp rcpt -- smtp rcpt addr */
	lua_createtable(ctx->lua, VectorLength(params_list), 0);	/* smtp rcpt addr -- smtp rcpt addr array */
	for (i = 0, param = (char **) VectorBase(params_list); *param != NULL; param++, i++) {
		lua_pushstring(ctx->lua, *param);	/* smtp rcpt addr array -- smtp rcpt addr array value */
		lua_rawseti(ctx->lua, -2, i);		/* smtp rcpt addr array value -- smtp rcpt addr array */
	}

	if (lua_pcall(ctx->lua, 2, 2, 0)) {	/* smtp rcpt addr array -- smtp code reply */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.rcpt: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	return lua_result(sess, ctx->lua, "smtp.rcpt", &stat_lua_rcpt);
}

SmtpfCode
luaData(Session *sess, va_list ignore)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaData);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_data()
	 * 	Return 250 on success or SMTP code and SMTP reply.
	 */
	lua_getglobal(ctx->lua, "smtp");
	lua_getfield(ctx->lua, -1, "data");
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);
		return SMTPF_CONTINUE;
	}

	if (lua_pcall(ctx->lua, 0, 2, 0)) {
		syslog(LOG_ERR, LOG_MSG(000) "smtp.data: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	return lua_result(sess, ctx->lua, "smtp.data", &stat_lua_data);
}

SmtpfCode
luaHeaders(Session *sess, va_list args)
{
	SmtpfCode rc = SMTPF_CONTINUE;
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaHeaders);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_headers(id, headers table)
	 * 	Return 0 (continue) on success or SMTP code and SMTP reply.
	 */

	return rc;
}

SmtpfCode
luaContent(Session *sess, va_list args)
{
	SmtpfCode rc = SMTPF_CONTINUE;
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaContent);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_chunk(id, chunk, size)
	 * 	Return 0 (continue) on success or SMTP code and SMTP reply.
	 */

	return rc;
}

SmtpfCode
luaDot(Session *sess, va_list ignore)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaDot);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_code, smtp_reply = smtp_dot(temp_msg_path)
	 * 	Return 250 on success or SMTP code and SMTP reply.
	 */
	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "dot");	/* smtp -- smtp dot */
	if (!lua_isfunction(ctx->lua, -1)) {
		lua_pop(ctx->lua, 2);		/* smtp dot -- */
		return SMTPF_CONTINUE;
	}

	lua_pushstring(ctx->lua, saveGetName(sess)); 	/* smtp dot -- smtp dot path */

	if (lua_pcall(ctx->lua, 1, 2, 0)) {	/* smtp dot path -- smtp code reply */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.dot: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 2);		/* smtp error -- */
		return SMTPF_CONTINUE;
	}

	return lua_result(sess, ctx->lua, "smtp.dot", &stat_lua_dot);
}


SmtpfCode
luaRset(Session *sess, va_list ignore)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaRset);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "trans");	/* smtp -- smtp trans */
	lua_pushnil(ctx->lua);			/* smtp trans -- smtp trans nil */
	lua_setfield(ctx->lua, -2, "id");	/* smtp trans nil -- smtp trans */
	lua_pushnil(ctx->lua);			/* smtp trans -- smtp trans nil */
	lua_setfield(ctx->lua, -2, "sender");	/* smtp trans nil -- smtp trans */
	lua_pop(ctx->lua, 1);			/* smtp trans -- smtp */

	/* smtp_rset()
	 */
	lua_getfield(ctx->lua, -1, "rset");	/* smtp -- smtp rset */
	if (lua_isfunction(ctx->lua, -1) && lua_pcall(ctx->lua, 0, 0, 0)) {	/* smtp rset -- smtp */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.rset: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
		lua_pop(ctx->lua, 1);		/* smtp error -- smtp */
	}
	lua_pop(ctx->lua, 1);			/* smtp -- */

	return SMTPF_CONTINUE;
}

SmtpfCode
luaClose(Session *sess, va_list ignore)
{
	LuaContext *ctx = filterGetContext(sess, lua_context);

	LOG_TRACE(sess, 000, luaClose);

	if (ctx->lua == NULL)
		return SMTPF_CONTINUE;

	/* smtp_close()
	 */
	lua_getglobal(ctx->lua, "smtp");	/* -- smtp */
	lua_getfield(ctx->lua, -1, "close");	/* smtp -- smtp close */
	if (lua_isfunction(ctx->lua, -1) && lua_pcall(ctx->lua, 0, 0, 0)) {	/* smtp close -- smtp */
		syslog(LOG_ERR, LOG_MSG(000) "smtp.close: %s", LOG_ARGS(sess), lua_tostring(ctx->lua, -1));
/*{LOG
Experimental module using Lua to script additional tests by creating a @PACKAGE_NAME@.lua script.
This module is undocumented and currently not provided in production code.
}*/
		lua_pop(ctx->lua, 1);		/* smtp error -- smtp */
	}
	lua_pop(ctx->lua, 1);			/* smtp -- */

	lua_close(ctx->lua);

	return SMTPF_CONTINUE;
}

#endif /* FILTER_LUA */


