/*
 * This file is part of lem-ssl.
 * Copyright 2011-2012 Emil Renner Berthing
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

struct ostream;

struct istream {
	struct ev_io w;
	SSL *ssl;
	struct ostream *twin;
	struct lem_parser *p;
	struct lem_inputbuf buf;
};

struct ostream {
	struct ev_io w;
	SSL *ssl;
	struct istream *twin;
	const char *data;
	size_t len;
};

static int
stream_closed(lua_State *T)
{
	struct ev_io *w;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	w = lua_touserdata(T, 1);
	lua_pushboolean(T, w->fd < 0);
	return 1;
}

static int
stream_busy(lua_State *T)
{
	struct ev_io *w;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	w = lua_touserdata(T, 1);
	lua_pushboolean(T, w->data != NULL);
	return 1;
}

static int
stream_interrupt(lua_State *T)
{
	struct ev_io *w;
	lua_State *S;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	w = lua_touserdata(T, 1);
	S = w->data;
	if (S == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "not busy");
		return 2;
	}

	lem_debug("interrupting io action");
	ev_io_stop(EV_G_ w);
	w->data = NULL;

	lua_settop(S, 0);
	lua_pushnil(S);
	lua_pushliteral(S, "interrupted");
	lem_queue(S, 2);

	lua_pushboolean(T, 1);
	return 1;
}

static struct istream *
istream_new(lua_State *T, SSL *ssl, int mt)
{
	struct istream *s;

	/* create userdata and set the metatable */
	s = lua_newuserdata(T, sizeof(struct istream));
	lua_pushvalue(T, mt);
	lua_setmetatable(T, -2);

	/* initialize userdata */
	ev_io_init(&s->w, NULL, SSL_get_fd(ssl), 0);
	s->w.data = NULL;
	s->ssl = ssl;
	s->twin = NULL;
	s->buf.start = s->buf.end = 0;

	return s;
}

static void
istream__close(struct istream *s)
{
	if (s->twin)
		s->twin->twin = NULL;
	else
		SSL_free(s->ssl);

	s->ssl = NULL;
	s->w.fd = -1;
}

static int
istream_gc(lua_State *T)
{
	struct istream *s = lua_touserdata(T, 1);

	lem_debug("collecting");
	if (s->w.fd < 0)
		return 0;

	istream__close(s);

	return 0;
}

static int
istream_close(lua_State *T)
{
	struct istream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	if (s->w.fd < 0) {
		lua_pushnil(T);
		lua_pushliteral(T, "already closed");
		return 2;
	}

	if (s->w.data != NULL) {
		lua_State *S = s->w.data;

		lem_debug("interrupting io action");
		ev_io_stop(EV_G_ &s->w);
		s->w.data = NULL;

		lua_settop(S, 0);
		lua_pushnil(S);
		lua_pushliteral(S, "interrupted");
		lem_queue(S, 2);
	}

	lem_debug("closing connection..");
	istream__close(s);

	lua_pushboolean(T, 1);
	return 1;
}

static void
stream_readp_handler(EV_P_ struct ev_io *w, int revents)
{
	struct istream *s = (struct istream *)w;
	lua_State *T = s->w.data;
	int ret;
	enum lem_preason reason;
	const char *msg;

	(void)revents;

again:
	ret = SSL_read(s->ssl, s->buf.buf + s->buf.end,
			LEM_INPUTBUF_SIZE - s->buf.end);
	lem_debug("read %d bytes from %d", ret, s->w.fd);
	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		s->buf.end += ret;
		ret = s->p->process(T, &s->buf);
		lem_debug("process return %d, b->start = %u, b->end = %u",
				ret, s->buf.start, s->buf.end);
		if (ret == 0)
			goto again;

		ev_io_stop(EV_A_ &s->w);
		s->w.data = NULL;
		lem_queue(T, ret);
		return;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		reason = LEM_PCLOSED;
		msg = "closed";
		break;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		if (s->w.events != EV_READ) {
			ev_io_stop(EV_A_ &s->w);
			s->w.events = EV_READ;
			ev_io_start(EV_A_ &s->w);
		}
		return;

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
		if (s->w.events != EV_WRITE) {
			ev_io_stop(EV_A_ &s->w);
			s->w.events = EV_WRITE;
			ev_io_start(EV_A_ &s->w);
		}
		return;

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e) {
				reason = LEM_PERROR;
				msg = ERR_reason_error_string(e);
			} else if (ret == 0) {
				reason = LEM_PCLOSED;
				msg = "closed";
			} else {
				reason = LEM_PERROR;
				msg = strerror(errno);
			}
		}
		break;

	case SSL_ERROR_SSL:
		lem_debug("SSL_ERROR_SSL");
		reason = LEM_PERROR;
		msg = ERR_reason_error_string(ERR_get_error());
		break;

	default:
		lem_debug("SSL_ERROR_* (default)");
		reason = LEM_PERROR;
		msg = "unexpected error from SSL library";
		break;
	}

	ev_io_stop(EV_A_ &s->w);
	s->w.data = NULL;

	if (s->p->destroy && (ret = s->p->destroy(T, &s->buf, reason)) > 0) {
		istream__close(s);
		lem_queue(T, ret);
		return;
	}

	lua_pushnil(T);
	lua_pushstring(T, msg);
	lem_queue(T, 2);
	istream__close(s);
}

static int
stream_readp(lua_State *T)
{
	struct istream *s;
	struct lem_parser *p;
	int ret;
	enum lem_preason reason;
	const char *msg;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	ret = lua_type(T, 2);
	if (ret != LUA_TUSERDATA && ret != LUA_TLIGHTUSERDATA)
		return luaL_argerror(T, 2, "expected userdata");

	s = lua_touserdata(T, 1);
	if (s->w.fd < 0) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	if (s->w.data != NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "busy");
		return 2;
	}

	p = lua_touserdata(T, 2);
	if (p->init)
		p->init(T, &s->buf);

again:
	ret = p->process(T, &s->buf);
	lem_debug("process return %d, b->start = %u, b->end = %u",
			ret, s->buf.start, s->buf.end);
	if (ret > 0)
		return ret;

	ret = SSL_read(s->ssl, s->buf.buf + s->buf.end,
			LEM_INPUTBUF_SIZE - s->buf.end);
	lem_debug("read %d bytes from %d", ret, s->w.fd);
	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		s->buf.end += ret;
		goto again;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		reason = LEM_PCLOSED;
		msg = "closed";
		break;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		s->w.events = EV_READ;
		goto yield;

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
		s->w.events = EV_WRITE;
		goto yield;

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e) {
				reason = LEM_PERROR;
				msg = ERR_reason_error_string(e);
			} else if (ret == 0) {
				reason = LEM_PCLOSED;
				msg = "closed";
			} else {
				reason = LEM_PERROR;
				msg = strerror(errno);
			}
		}
		break;

	case SSL_ERROR_SSL:
		lem_debug("SSL_ERROR_SSL");
		reason = LEM_PERROR;
		msg = ERR_reason_error_string(ERR_get_error());
		break;

	default:
		lem_debug("SSL_ERROR_* (default)");
		reason = LEM_PERROR;
		msg = "unexpected error from SSL library";
		break;
	}

	if (s->p->destroy && (ret = s->p->destroy(T, &s->buf, reason)) > 0)
		return ret;

	lua_pushnil(T);
	lua_pushstring(T, msg);
	istream__close(s);
	return 2;

yield:
	s->p = p;
	s->w.data = T;
	s->w.cb = stream_readp_handler;
	ev_io_start(EV_G_ &s->w);
	return lua_yield(T, lua_gettop(T));
}

static struct ostream *
ostream_new(lua_State *T, SSL *ssl, int mt)
{
	struct ostream *s;

	/* create userdata and set the metatable */
	s = lua_newuserdata(T, sizeof(struct ostream));
	lua_pushvalue(T, mt);
	lua_setmetatable(T, -2);

	/* initialize userdata */
	ev_io_init(&s->w, NULL, SSL_get_fd(ssl), 0);
	s->w.data = NULL;
	s->ssl = ssl;
	s->twin = NULL;

	return s;
}

static void
ostream__close(struct ostream *s)
{
	if (s->twin)
		s->twin->twin = NULL;
	else
		SSL_free(s->ssl);

	s->ssl = NULL;
	s->w.fd = -1;
}

static int
ostream_gc(lua_State *T)
{
	struct ostream *s = lua_touserdata(T, 1);

	lem_debug("collecting");
	if (s->w.fd < 0)
		return 0;

	ostream__close(s);

	return 0;
}

static int
ostream_close(lua_State *T)
{
	struct ostream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	if (s->w.fd < 0) {
		lua_pushnil(T);
		lua_pushliteral(T, "already closed");
		return 2;
	}

	if (s->w.data != NULL) {
		lua_State *S = s->w.data;

		lem_debug("interrupting io action");
		ev_io_stop(EV_G_ &s->w);
		s->w.data = NULL;

		lua_settop(S, 0);
		lua_pushnil(S);
		lua_pushliteral(S, "interrupted");
		lem_queue(S, 2);
	}

	lem_debug("closing connection..");
	ostream__close(s);

	lua_pushboolean(T, 1);
	return 1;
}

static void
stream_write_handler(EV_P_ struct ev_io *w, int revents)
{
	struct ostream *s = (struct ostream *)w;
	lua_State *T = s->w.data;
	int ret;
	const char *msg;

	(void)revents;

again:
	ret = SSL_write(s->ssl, s->data, s->len);
	lem_debug("wrote %d bytes to %d", ret, s->w.fd);
	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		s->len -= ret;
		if (s->len > 0) {
			s->data += ret;
			goto again;
		}

		ev_io_stop(EV_A_ &s->w);
		s->w.data = NULL;

		lua_pushboolean(T, 1);
		lem_queue(T, 1);
		return;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		msg = "closed";
		break;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		if (s->w.events != EV_READ) {
			ev_io_stop(EV_A_ &s->w);
			s->w.events = EV_READ;
			ev_io_start(EV_A_ &s->w);
		}
		return;

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
		if (s->w.events != EV_WRITE) {
			ev_io_stop(EV_A_ &s->w);
			s->w.events = EV_WRITE;
			ev_io_start(EV_A_ &s->w);
		}
		return;

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e)
				msg = ERR_reason_error_string(e);
			else if (ret == 0)
				msg = "closed";
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
		break;
	}

	ev_io_stop(EV_A_ &s->w);
	s->w.data = NULL;

	lua_pushnil(T);
	lua_pushstring(T, msg);
	lem_queue(T, 2);
}

static int
stream_write(lua_State *T)
{
	struct ostream *s;
	int ret;
	const char *msg;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	luaL_checktype(T, 2, LUA_TSTRING);

	s = lua_touserdata(T, 1);
	if (s->w.fd < 0) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	if (s->w.data != NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "busy");
		return 2;
	}

	s->data = lua_tolstring(T, 2, &s->len);
	if (s->len == 0) {
		lua_pushboolean(T, 1);
		return 1;
	}

again:
	ret = SSL_write(s->ssl, s->data, s->len);
	lem_debug("wrote %d bytes to %d", ret, s->w.fd);
	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		s->len -= ret;
		if (s->len > 0) {
			s->data += ret;
			goto again;
		}
		lua_pushboolean(T, 1);
		return 1;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		msg = "closed";
		break;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		s->w.events = EV_READ;
		s->w.cb = stream_write_handler;
		ev_io_start(EV_G_ &s->w);
		lua_settop(T, 1);
		return lua_yield(T, 1);

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
		s->w.events = EV_WRITE;
		s->w.cb = stream_write_handler;
		ev_io_start(EV_G_ &s->w);
		lua_settop(T, 1);
		return lua_yield(T, 1);

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e)
				msg = ERR_reason_error_string(e);
			else if (ret == 0)
				msg = "closed";
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
		break;
	}

	lua_pushnil(T);
	lua_pushstring(T, msg);
	ostream__close(s);
	return 2;
}
