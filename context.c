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

static int
context_close(lua_State *T)
{
	struct lem_ssl_context *c;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	c = lua_touserdata(T, 1);

	if (c->ctx == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	SSL_CTX_free(c->ctx);
	c->ctx = NULL;

	lua_pushboolean(T, 1);
	return 1;
}

static int
context_new(lua_State *T)
{
	SSL_CTX *ctx;
	struct lem_ssl_context *c;

	ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL) {
		lua_pushnil(T);
		lua_pushfstring(T, "unable to initialize SSL context: %s",
		                ERR_reason_error_string(ERR_get_error()));
		return 2;
	}

	/* create userdata and set the metatable */
	c = lua_newuserdata(T, sizeof(struct lem_ssl_context));
	lua_pushvalue(T, lua_upvalueindex(1));
	lua_setmetatable(T, -2);

	c->ctx = ctx;

	return 1;
}

static void
connect_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = stream_check_error(s->T, s, SSL_connect(s->ssl),
	                         "error establishing SSL connection: %s");
	if (ret == 0)
		return;

	stream_io_unregister(s);
	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
context_connect(lua_State *T)
{
	struct lem_ssl_context *c;
	const char *hostname;
	int port;
	BIO *bio;
	SSL *ssl;
	int ret;
	const char *msg;
	struct lem_ssl_stream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	c = lua_touserdata(T, 1);
	hostname = luaL_checkstring(T, 2);
	port = (int)luaL_optnumber(T, 3, -1);

	if (c->ctx == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	bio = BIO_new(BIO_s_connect());
	if (bio == NULL) {
		lua_pushnil(T);
		lua_pushfstring(T, "error creating BIO: %s",
		                ERR_reason_error_string(ERR_get_error()));
		return 2;
	}
	BIO_set_conn_hostname(bio, hostname);
	if (port > 0)
		BIO_set_conn_int_port(bio, (char *)&port);
	BIO_set_nbio(bio, 1);

	ssl = SSL_new(c->ctx);
	if (ssl == NULL) {
		lua_pushnil(T);
		lua_pushfstring(T, "error creating SSL connection: %s",
		                ERR_reason_error_string(ERR_get_error()));
		return 2;
	}
	SSL_set_bio(ssl, bio, bio);

	ret = SSL_connect(ssl);
	switch (SSL_get_error(ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		s = stream_new(T, ssl, NULL, 0);
		return 1;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		msg = "connection closed unexpectedly";
		break;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		lua_settop(T, 0);
		s = stream_new(T, ssl, connect_handler, EV_READ);
		s->T = T;
		ev_io_start(EV_G_ &s->w);
		return lua_yield(T, 1);

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
	case SSL_ERROR_WANT_CONNECT:
		lem_debug("SSL_ERROR_WANT_CONNECT");
		lua_settop(T, 0);
		s = stream_new(T, ssl, connect_handler, EV_WRITE);
		s->T = T;
		ev_io_start(EV_G_ &s->w);
		return lua_yield(T, 1);

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e)
				msg = ERR_reason_error_string(e);
			else if (ret == 0)
				msg = "connection closed unexpectedly";
			else
				msg = strerror(errno);

		}
		break;

	case SSL_ERROR_SSL:
		lem_debug("SSL_ERROR_SSL");
		msg = ERR_reason_error_string(ERR_get_error());
		break;

	default:
		lem_debug("SSL_ERROR_* (default)");
		msg = "unexpected error from SSL library";
	}

	lua_pushnil(T);
	lua_pushfstring(T, "error establishing SSL connection: %s", msg);
	SSL_free(ssl);
	return 2;
}


