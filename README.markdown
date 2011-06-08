lem-ssl
===========


About
-----

lem-ssl is a library for the [Lua Event Machine][lem] to create and accept encrypted
connections using [OpenSSL][openssl].

[lem]: https://github.com/esmil/lem
[openssl]: http://openssl.org


Installation
------------

Get the source and do

    make
    make install

This installs the library under `/usr/local/lib/lua/5.1/`.
Use

    make NDEBUG=1
    make PREFIX=<your custom path> install

to avoid a load of debugging output and install to `<your custom path>/lib/lua/5.1/`.


Usage
-----

Import the module using something like

    local ssl = require 'lem.ssl'

This sets `ssl` to a table with the following functions.

* __ssl.newcontext()__

  This function creates a context needed by the OpenSSL library.
  This context will be shared by all connections created using it.

The metatable of context objects can be found under __ssl.Context__,
and the following methods are available on them.

* __context:connect(address, [port])__

  This function opens a new secured TCP connection to the specified address using
  this context.
  The address is passed directly on to the OpenSSL library, and thus supports
  addresses of the form "&lt;URL or IP&gt;:&lt;port number or name&gt;".
  However if a port number is specified as the second argument to the method,
  that takes precedence.

  The current coroutine will be suspended until the connection is fully
  established or an error occurs.

  On succes this method will return a new stream object representing the connection.
  Otherwise `nil` followed by an error message will be returned.

The metatable of stream objects can be found under __ssl.Stream__, and the
following methods are available on SSL streams.

* __stream:closed()__

  Returns `true` when the stream is closed, `false` otherwise.

* __stream:busy()__

  Returns `true` when another coroutine is waiting for IO on this stream,
  `false` otherwise.

* __stream:close()__

  Closes the stream. If the stream is busy, this also interrupts the IO
  action on the stream.

  Returns `true` on succes or otherwise `nil` followed by an error message.
  If the stream is already closed the error message will be `'already closed'`.

* __stream:interrupt()__

  Interrupt any coroutine waiting for IO on the stream.

  Returns `true` on success and `nil, 'not busy'` if no coroutine is waiting
  for connections on the server object.

* __stream:read([mode])__

  Read data from the stream. The `mode` argument can be one of the following:

    - a number: read the given number of bytes from the stream
    - "\*a": read all data from stream until the stream is closed
    - "\*l": read a line (read up to and including the next '\n' character)

  If there is not enough data immediately available the current coroutine will
  be suspended until there is.

  However if the method is called without the mode argument, it will return
  what is immediately available on the stream (up to a certain size limit).
  Only if there is no data immediately available will the current coroutine
  be suspended until there is.

  On success this method will return the data read from stream in a Lua string.
  Otherwise it will return `nil` followed by an error message.
  If another coroutine is waiting for IO on the stream the error message
  will be `'busy'`.
  If the stream was interrupted (eg. by another coroutine calling
  `stream:interrupt()`, or `stream:close()`) the error message will be
  `'interrupted'`.
  If the stream is closed either before calling the method or closed
  from the other end during the read the error message will be `'closed'`.

* __stream:write(data)__

  Write the given data, which must be a Lua string, to the stream.
  If the data cannot be immediately written to the stream the current
  coroutine will be suspended until all data is written.

  Returns `true` on success or otherwise `nil` followed by an error message.
  If another coroutine is waiting for IO on the stream the error message
  will be `'busy'`.
  If the stream was interrupted (eg. by another coroutine calling
  `stream:interrupt()`, or `stream:close()`) the error message will be
  `'interrupted'`.
  If the stream is closed either before calling the method or closed
  from the other end during the write the error message will be `'closed'`.


License
-------

lem-ssl is free software. It is distributed under the terms of the
[GNU General Public License][gpl].

[gpl]: http://www.fsf.org/licensing/licenses/gpl.html


Contact
-------

Please send bug reports, patches, feature requests, praise and general gossip
to me, Emil Renner Berthing <esmil@mailme.dk>.
