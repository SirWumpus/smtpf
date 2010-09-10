/*
 * lua.h
 *
 * Copyright 2010 by Anthony Howe. All rights reserved.
 */

#ifndef __lua_h__
#define __lua_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if !defined(LUA_FILE)
# define LUA_FILE		CF_DIR "/" _NAME ".lua"
#endif

extern Verbose verb_lua;

extern Stats stat_lua_connect;
extern Stats stat_lua_helo;
extern Stats stat_lua_mail;
extern Stats stat_lua_rcpt;
extern Stats stat_lua_data;
extern Stats stat_lua_headers;
extern Stats stat_lua_content;
extern Stats stat_lua_dot;

typedef struct {
	lua_State *lua;
} LuaContext;

extern FilterContext lua_context;

extern SmtpfCode luaRegister(Session *sess, va_list ignore);
extern SmtpfCode luaConnect0(Session *sess, va_list args);
extern SmtpfCode luaConnect1(Session *sess, va_list args);
extern SmtpfCode luaHelo(Session *sess, va_list args);
extern SmtpfCode luaMail(Session *sess, va_list args);
extern SmtpfCode luaRcpt(Session *sess, va_list args);
extern SmtpfCode luaData(Session *sess, va_list ignore);
extern SmtpfCode luaHeaders(Session *sess, va_list args);
extern SmtpfCode luaContent(Session *sess, va_list args);
extern SmtpfCode luaDot(Session *sess, va_list ignore);
extern SmtpfCode luaRset(Session *sess, va_list ignore);
extern SmtpfCode luaClose(Session *sess, va_list ignore);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __lua_h__ */
