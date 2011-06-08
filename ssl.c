/*
 * This file is part of lem-ssl.
 * Copyright 2011 Emil Renner Berthing
 *
 * lem-ssl is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * lem-ssl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lem-ssl.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl.h"

#include "stream.c"
#include "context.c"

int
luaopen_lem_ssl(lua_State *L)
{
	/* initialize ssl library */
	SSL_library_init();
	SSL_load_error_strings();

	/* create module table */
	lua_newtable(L);

	/* create metatable for stream objects */
	lua_newtable(L);
	/* mt.__index = mt */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	/* mt.__gc = <stream_gc> */
	lua_pushcfunction(L, stream_gc);
	lua_setfield(L, -2, "__gc");
	/* mt.closed = <stream_closed> */
	lua_pushcfunction(L, stream_closed);
	lua_setfield(L, -2, "closed");
	/* mt.busy = <stream_busy> */
	lua_pushcfunction(L, stream_busy);
	lua_setfield(L, -2, "busy");
	/* mt.close = <stream_close> */
	lua_pushcfunction(L, stream_close);
	lua_setfield(L, -2, "close");
	/* mt.read = <stream_read> */
	lua_pushcfunction(L, stream_read);
	lua_setfield(L, -2, "read");
	/* mt.write = <stream_write> */
	lua_pushcfunction(L, stream_write);
	lua_setfield(L, -2, "write");
	/* mt.interrupt = <stream_interrupt> */
	lua_pushcfunction(L, stream_interrupt);
	lua_setfield(L, -2, "interrupt");
	/* insert table */
	lua_setfield(L, -2, "Stream");

	/* create metatable for context objects */
	lua_newtable(L);
	/* mt.__index = mt */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	/* mt.__gc = <context_close> */
	lua_pushcfunction(L, context_close);
	lua_setfield(L, -2, "__gc");
	/* mt.connect = <context_connect> */
	lua_getfield(L, -2, "Stream"); /* upvalue 1 = Stream */
	lua_pushcclosure(L, context_connect, 1);
	lua_setfield(L, -2, "connect");
	/* insert table */
	lua_setfield(L, -2, "Context");

	/* insert newcontext function */
	lua_getfield(L, -1, "Context"); /* upvalue 1 = Context */
	lua_pushcclosure(L, context_new, 1);
	lua_setfield(L, -2, "newcontext");

	return 1;
}
