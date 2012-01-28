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
#include <lem/streams.h>

#include "stream.c"
#include "context.c"

int
luaopen_lem_ssl_core(lua_State *L)
{
	/* initialize ssl library */
	SSL_library_init();
	SSL_load_error_strings();

	/* create module table */
	lua_createtable(L, 0, 4);

	/* create metatable for IStream objects */
	lua_createtable(L, 0, 8);
	/* mt.__index = mt */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	/* mt.__gc = <istream_gc> */
	lua_pushcfunction(L, istream_gc);
	lua_setfield(L, -2, "__gc");
	/* mt.closed = <stream_closed> */
	lua_pushcfunction(L, stream_closed);
	lua_setfield(L, -2, "closed");
	/* mt.busy = <stream_busy> */
	lua_pushcfunction(L, stream_busy);
	lua_setfield(L, -2, "busy");
	/* mt.interrupt = <stream_interrupt> */
	lua_pushcfunction(L, stream_interrupt);
	lua_setfield(L, -2, "interrupt");
	/* mt.close = <istream_close> */
	lua_pushcfunction(L, istream_close);
	lua_setfield(L, -2, "close");
	/* mt.readp = <stream_readp> */
	lua_pushcfunction(L, stream_readp);
	lua_setfield(L, -2, "readp");
	/* insert table */
	lua_setfield(L, -2, "IStream");

	/* create metatable for OStream objects */
	lua_createtable(L, 0, 7);
	/* mt.__index = mt */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	/* mt.__gc = <ostream_gc> */
	lua_pushcfunction(L, ostream_gc);
	lua_setfield(L, -2, "__gc");
	/* mt.closed = <stream_closed> */
	lua_pushcfunction(L, stream_closed);
	lua_setfield(L, -2, "closed");
	/* mt.busy = <stream_busy> */
	lua_pushcfunction(L, stream_busy);
	lua_setfield(L, -2, "busy");
	/* mt.interrupt = <stream_interrupt> */
	lua_pushcfunction(L, stream_interrupt);
	lua_setfield(L, -2, "interrupt");
	/* mt.close = <ostream_close> */
	lua_pushcfunction(L, ostream_close);
	lua_setfield(L, -2, "close");
	/* mt.write = <stream_write> */
	lua_pushcfunction(L, stream_write);
	lua_setfield(L, -2, "write");
	/* insert table */
	lua_setfield(L, -2, "OStream");

	/* create metatable for context objects */
	lua_createtable(L, 0, 3);
	/* mt.__index = mt */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	/* mt.__gc = <context_close> */
	lua_pushcfunction(L, context_close);
	lua_setfield(L, -2, "__gc");
	/* mt.connect = <context_connect> */
	lua_getfield(L, -2, "IStream"); /* upvalue 1 = IStream */
	lua_getfield(L, -3, "OStream"); /* upvalue 2 = OStream */
	lua_pushcclosure(L, context_connect, 2);
	lua_setfield(L, -2, "connect");
	/* insert table */
	lua_setfield(L, -2, "Context");

	/* insert newcontext function */
	lua_getfield(L, -1, "Context"); /* upvalue 1 = Context */
	lua_pushcclosure(L, context_new, 1);
	lua_setfield(L, -2, "newcontext");

	return 1;
}
