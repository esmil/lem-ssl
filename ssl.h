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

#ifndef LEM_SSL_H
#define LEM_SSL_H

#include <lem.h>

#define LEM_SSL_STREAM_BUFSIZE 1024

struct lem_ssl_context {
	SSL_CTX *ctx;
};

struct lem_ssl_stream {
	struct ev_io w;
	lua_State *T;
	SSL *ssl;
	char *readp;
	char *writep;

	union {
		struct {
			int parts;
			int target;
		} in;
		struct {
			const char *buf;
			size_t len;
		} write;
	};

	char buf[LEM_SSL_STREAM_BUFSIZE];
};

#endif
