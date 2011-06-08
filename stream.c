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

static inline void
stream_io_register(struct lem_ssl_stream *s, int events)
{
	if (s->w.events == events)
		return;

	if (s->w.events)
		ev_io_stop(EV_G_ &s->w);

	s->w.events = events;
	ev_io_start(EV_G_ &s->w);
}

static inline void
stream_io_unregister(struct lem_ssl_stream *s)
{
	if (s->w.events == 0)
		return;

	ev_io_stop(EV_G_ &s->w);
	s->w.events = 0;
}

static int
stream_check_error(lua_State *T,
                    struct lem_ssl_stream *s, int ret,
                    const char *fmt)
{
	const char *msg;

	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_NONE:
		lem_debug("SSL_ERROR_NONE");
		return 1;

	case SSL_ERROR_ZERO_RETURN:
		lem_debug("SSL_ERROR_ZERO_RETURN");
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		goto error;

	case SSL_ERROR_WANT_READ:
		lem_debug("SSL_ERROR_WANT_READ");
		stream_io_register(s, EV_READ);
		return 0;

	case SSL_ERROR_WANT_WRITE:
		lem_debug("SSL_ERROR_WANT_WRITE");
	case SSL_ERROR_WANT_CONNECT:
		lem_debug("SSL_ERROR_WANT_CONNECT");
		stream_io_register(s, EV_WRITE);
		return 0;

	case SSL_ERROR_SYSCALL:
		lem_debug("SSL_ERROR_SYSCALL");
		{
			long e = ERR_get_error();

			if (e)
				msg = ERR_reason_error_string(e);
			else if (ret == 0) {
				lua_pushnil(T);
				lua_pushliteral(T, "closed");
				goto error;
			} else
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
	lua_pushfstring(T, fmt, msg);

error:
	stream_io_unregister(s);
	SSL_free(s->ssl);
	s->ssl = NULL;
	return 2;
}


static struct lem_ssl_stream *
stream_new(lua_State *T, SSL *ssl,
           void (*cb)(EV_P_ struct ev_io *w, int revents), int events)
{
	struct lem_ssl_stream *s;

	/* create userdata and set the metatable */
	s = lua_newuserdata(T, sizeof(struct lem_ssl_stream));
	lua_pushvalue(T, lua_upvalueindex(1));
	lua_setmetatable(T, -2);

	/* initialize userdata */
	ev_io_init(&s->w, cb, SSL_get_fd(ssl), events);
	s->T = NULL;
	s->ssl = ssl;
	s->readp = s->writep = s->buf;

	return s;
}

static int
stream_closed(lua_State *T)
{
	struct lem_ssl_stream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	lua_pushboolean(T, s->ssl == NULL);
	return 1;
}

static int
stream_busy(lua_State *T)
{
	struct lem_ssl_stream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	lua_pushboolean(T, s->T != NULL);
	return 1;
}

static int
stream_gc(lua_State *T)
{
	struct lem_ssl_stream *s = lua_touserdata(T, 1);

	lem_debug("collecting");
	if (s->ssl == NULL)
		return 0;;

	SSL_free(s->ssl);
	s->ssl = NULL;

	return 0;
}

static int
stream_close(lua_State *T)
{
	struct lem_ssl_stream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	if (s->ssl == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "already closed");
		return 2;
	}

	if (s->T != NULL) {
		lem_debug("interrupting io action");
		stream_io_unregister(s);
		lua_settop(s->T, 0);
		lua_pushnil(s->T);
		lua_pushliteral(s->T, "interrupted");
		lem_queue(s->T, 2);
		s->T = NULL;
	}

	lem_debug("closing connection..");

	SSL_free(s->ssl);
	s->ssl = NULL;

	lua_pushboolean(T, 1);
	return 1;
}

static int
stream_interrupt(lua_State *T)
{
	struct lem_ssl_stream *s;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	s = lua_touserdata(T, 1);
	if (s->T == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "not busy");
		return 2;
	}

	lem_debug("interrupting io action");
	stream_io_unregister(s);
	lua_settop(s->T, 0);
	lua_pushnil(s->T);
	lua_pushliteral(s->T, "interrupted");
	lem_queue(s->T, 2);
	s->T = NULL;

	lua_pushboolean(T, 1);
	return 1;
}

/*
 * read available data
 */
static int
try_read_available(lua_State *T, struct lem_ssl_stream *s)
{
	int count;
	int ret;

	count = SSL_read(s->ssl, s->buf, LEM_SSL_STREAM_BUFSIZE);
	lem_debug("read %d bytes", count);
	ret = stream_check_error(T, s, count,
	                         "error reading from SSL stream: %s");
	if (ret != 1)
		return ret;

	stream_io_unregister(s);
	lua_pushlstring(T, s->buf, (size_t)count);
	return 1;
}

static void
read_available_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = try_read_available(s->T, s);
	if (ret == 0)
		return;

	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
stream_read_available(lua_State *T, struct lem_ssl_stream *s)
{
	size_t size = s->writep - s->readp;
	int ret;

	if (size > 0) {
		lua_pushfstring(T, s->readp, size);
		s->readp = s->writep = s->buf;
		return 1;
	}

	ret = try_read_available(T, s);
	if (ret > 0)
		return ret;

	s->T = T;
	s->w.cb = read_available_handler;
	return lua_yield(T, 0);
}

/*
 * read all data until stream closes
 */
static void
pushbuf(lua_State *T, struct lem_ssl_stream *s)
{
	lua_pushlstring(T, s->readp, s->writep - s->readp);
	s->in.parts++;
	s->readp = s->writep = s->buf;
}

static int
try_read_all(lua_State *T, struct lem_ssl_stream *s)
{
	const char *msg;

	while (1) {
		int count = LEM_SSL_STREAM_BUFSIZE - (s->writep - s->buf);

		if (count == 0) {
			pushbuf(T, s);
			count = LEM_SSL_STREAM_BUFSIZE;
		}

		count = SSL_read(s->ssl, s->writep, count);
		lem_debug("read %d bytes", count);
		switch (SSL_get_error(s->ssl, count)) {
		case SSL_ERROR_NONE:
			lem_debug("SSL_ERROR_NONE");
			break;

		case SSL_ERROR_ZERO_RETURN:
			lem_debug("SSL_ERROR_ZERO_RETURN");
			goto out;

		case SSL_ERROR_WANT_READ:
			lem_debug("SSL_ERROR_WANT_READ");
			stream_io_register(s, EV_READ);
			return 0;

		case SSL_ERROR_WANT_WRITE:
			lem_debug("SSL_ERROR_WANT_WRITE");
		case SSL_ERROR_WANT_CONNECT:
			lem_debug("SSL_ERROR_WANT_CONNECT");
			stream_io_register(s, EV_WRITE);
			return 0;

		case SSL_ERROR_SYSCALL:
			lem_debug("SSL_ERROR_SYSCALL");
			{
				long e = ERR_get_error();

				if (e)
					msg = ERR_reason_error_string(e);
				else if (count == 0)
					goto out;
				else
					msg = strerror(errno);
			}
			goto error;

		case SSL_ERROR_SSL:
			lem_debug("SSL_ERROR_SSL");
			msg = ERR_reason_error_string(ERR_get_error());
			goto error;

		default:
			lem_debug("SSL_ERROR_* (default)");
			msg = "unexpected error from SSL library";
			goto error;
		}

		s->writep += count;
	}
out:
	pushbuf(T, s);
	lua_concat(T, s->in.parts);

	stream_io_unregister(s);
	SSL_free(s->ssl);
	s->ssl = NULL;
	return 1;

error:
	lua_pushnil(T);
	lua_pushfstring(T, "error reading from SSL stream: %s", msg);

	stream_io_unregister(s);
	SSL_free(s->ssl);
	s->ssl = NULL;
	return 2;
}

static void
read_all_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = try_read_all(s->T, s);
	if (ret == 0)
		return;

	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
stream_read_all(lua_State *T, struct lem_ssl_stream *s)
{
	int ret = try_read_all(T, s);

	if (ret > 0)
		return ret;

	s->T = T;
	s->w.cb = read_all_handler;
	return lua_yield(T, lua_gettop(T));
}

/*
 * read a specified number of bytes
 */
static int
try_read_target(lua_State *T, struct lem_ssl_stream *s)
{
	do {
		int count = LEM_SSL_STREAM_BUFSIZE - (s->writep - s->buf);
		int ret;

		if (count == 0) {
			pushbuf(T, s);
			count = LEM_SSL_STREAM_BUFSIZE;
		}

		if (count > s->in.target)
			count = s->in.target;

		count = SSL_read(s->ssl, s->writep, count);
		lem_debug("read %d bytes", count);
		ret = stream_check_error(T, s, count,
		                         "error reading from SSL stream: %s");
		if (ret != 1)
			return ret;

		s->writep += count;
		s->in.target -= count;
	} while (s->in.target > 0);

	stream_io_unregister(s);
	pushbuf(T, s);
	lua_concat(T, s->in.parts);
	return 1;
}

static void
read_target_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = try_read_target(s->T, s);
	if (ret == 0)
		return;

	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
stream_read_target(lua_State *T, struct lem_ssl_stream *s)
{
	int size = s->writep - s->readp;
	int ret;

	if (size >= s->in.target) {
		lem_debug("%d bytes already in buffer", size);
		lua_pushlstring(T, s->readp, s->in.target);
		s->readp += s->in.target;
		if (s->readp == s->writep)
			s->readp = s->writep = s->buf;
		return 1;
	}

	s->in.target -= size;

	ret = try_read_target(T, s);
	if (ret > 0)
		return ret;

	s->T = T;
	s->w.cb = read_target_handler;
	return lua_yield(T, lua_gettop(T));
}

/*
 * read a line
 */
static int
try_read_line(lua_State *T, struct lem_ssl_stream *s)
{
	char *p;

	while (1) {
		int ret;
		int count = LEM_SSL_STREAM_BUFSIZE - (s->writep - s->buf);

		if (count == 0) {
			pushbuf(T, s);
			count = LEM_SSL_STREAM_BUFSIZE;
		}

		count = SSL_read(s->ssl, s->writep, count);
		lem_debug("read %d bytes", count);
		ret = stream_check_error(T, s, count,
		                         "error reading from SSL stream: %s");
		if (ret != 1)
			return ret;

		p = s->writep;
		s->writep += count;
		while (p < s->writep) {
			if (*p++ == '\n')
				goto out;
		}
	}
out:
	stream_io_unregister(s);

	lua_pushlstring(T, s->readp, p - s->readp);
	s->in.parts++;
	s->readp = p;
	if (s->readp == s->writep)
		s->readp = s->writep = s->buf;

	lua_concat(T, s->in.parts);

	return 1;
}

static void
read_line_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = try_read_line(s->T, s);
	if (ret == 0)
		return;

	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
stream_read_line(lua_State *T, struct lem_ssl_stream *s)
{
	int ret;
	char *p = s->readp;

	while (p < s->writep) {
		if (*p++ == '\n') {
			lua_pushlstring(T, s->readp, p - s->readp);
			s->readp = p;
			if (s->readp == s->writep)
				s->readp = s->writep = s->buf;
			return 1;
		}
	}

	if (s->readp > s->buf) {
		size_t len = s->writep - s->readp;

		memmove(s->buf, s->readp, len);
		s->readp = s->buf;
		s->writep = s->buf + len;
	}

	ret = try_read_line(T, s);
	if (ret > 0)
		return ret;

	s->T = T;
	s->w.cb = read_line_handler;
	return lua_yield(T, lua_gettop(T));
}

/*
 * client:read() method
 */
static int
stream_read(lua_State *T)
{
	struct lem_ssl_stream *s;
	const char *mode;

	luaL_checktype(T, 1, LUA_TUSERDATA);

	s = lua_touserdata(T, 1);
	if (s->ssl == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	if (s->T != NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "busy");
		return 2;
	}

	if (lua_gettop(T) == 1) {
		lua_settop(T, 0);
		return stream_read_available(T, s);
	}

	s->in.parts = 0;

	if (lua_isnumber(T, 2)) {
		s->in.target = (int)lua_tonumber(T, 2);
		lua_settop(T, 0);
		return stream_read_target(T, s);
	}

	mode = lua_tostring(T, 2);
	if (mode == NULL || mode[0] != '*')
		return luaL_error(T, "invalid mode string");

	lua_settop(T, 0);
	switch (mode[1]) {
	case 'a':
		return stream_read_all(T, s);
	case 'l':
		return stream_read_line(T, s);
	}

	return luaL_error(T, "invalid mode string");
}

static int
try_write(lua_State *T, struct lem_ssl_stream *s)
{
	do {
		int ret;
		int count = SSL_write(s->ssl, s->write.buf, s->write.len);

		lem_debug("wrote = %d bytes", count);
		ret = stream_check_error(T, s, count,
		                         "error writing to SSL stream: %s");
		if (ret != 1)
			return ret;

		s->write.buf += count;
		s->write.len -= count;
	} while (s->write.len > 0);

	stream_io_unregister(s);
	lua_pushboolean(T, 1);
	return 1;
}

static void
write_handler(EV_P_ struct ev_io *w, int revents)
{
	struct lem_ssl_stream *s = (struct lem_ssl_stream *)w;
	int ret;

	(void)revents;

	ret = try_write(s->T, s);
	if (ret == 0)
		return;

	lem_queue(s->T, ret);
	s->T = NULL;
}

static int
stream_write(lua_State *T)
{
	struct lem_ssl_stream *s;
	int ret;

	luaL_checktype(T, 1, LUA_TUSERDATA);
	luaL_checktype(T, 2, LUA_TSTRING);

	s = lua_touserdata(T, 1);
	if (s->ssl == NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "closed");
		return 2;
	}

	if (s->T != NULL) {
		lua_pushnil(T);
		lua_pushliteral(T, "busy");
		return 2;
	}

	s->write.buf = lua_tolstring(T, 2, &s->write.len);
	if (s->write.len == 0) {
		lua_pushboolean(T, 1);
		return 1;
	}

	ret = try_write(T, s);
	if (ret > 0)
		return ret;

	s->T = T;
	s->w.cb = write_handler;
	lua_settop(T, 2);
	return lua_yield(T, 2);
}
