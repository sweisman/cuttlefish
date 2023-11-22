# cuttlefish
Reverse Tunnel and Remote Access Toolkit

This code was in legitimate production use for many years.

### Cuttlefish is a RAT that provides three operations:

1. Upload and download files.
2. Execute a command passively or actively, by redirecting STDIN and STDOUT.
3. Forward network connections to a selected host and port.

All other features RATs boast supporting, whether legitimate or nefarious, can be implemented via these three fundamental operations.
Cuttlefish lacks the broad feature set of other RATs, but it is the most extensible and powerful RAT available, along with the most compact.

The client runs on Windows, and is statically compiled with OpenSSL or WolfSSL (or another similar library). It is written using vanilla ANSI C and the stock Windows 32 API with no extensions.
It uses a flexible multithreaded design to handle command execution and file transfers.
Further, it depends on no DLLs.

It is typically invoked and managed with a Service Manager like [NSSM](https://nssm.cc/).

The server is likewise written in ANSI C intended to run in a Linux or Unix environment. It is designed to be spawned by `stunnel`, which establishes and maintains the connection.
Each client connection has its own server to accept and process commands.

The server and client support multiple bidirectional operations in flight simultaneously.

### Server Parameters
```
-p: command pipe dir (where the unix domain socket is opened to control the connection)
-l: log dir (very detailed logging of each connection)
```

### Client Parameters
```
-u: server host to connect to
-p: server port
-w: working directory
-l: log file
-s: public server certificate file
-c: public client certificate file
```

### Server Certificate

To create a server certificate, follow the steps in the [Stunnel HOWTO](https://www.stunnel.org/howto.html),
section *Generating the stunnel certificate and private key (pem)*.

### Client certificate

```
cd /etc/stunnel
mkdir clients # if doesn't exist
```

File used to create a new client certificate:

The parameter `commonName` is used by convention to store the unique id to control and interact with a specific client.
Where `commonName`, by convention, is the code used to control the client, send commands and data to it, and receive data in return. It is the unique ID by which the connecting client is identified.

Create a new directory:

```
mkdir /etc/stunnel/clients/$commonName
```

In `$commonNameDir` (/etc/stunnel/clients/$commonName), save the following as cert.conf.


```
[req]
distinguished_name          = req_distinguished_name
x509_extensions             = v3_ca
prompt                      = no
[v3_ca]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer:always
basicConstraints            = CA:true
[req_distinguished_name]
countryName                 = US
organizationName            = $organizationName
stateOrProvinceName         = $stateOrProvinceName
localityName                = $localityName
emailAddress                = $emailAddress
commonName                  = $commonName
```

To create a new client:

```
/usr/bin/openssl req -new -batch -config "$commonNameDir/cert.conf" -nodes -days 9999 -newkey rsa:2048 -x509 -keyout "$commonNameDir/key.pem" -out "$commonNameDir/cert.pem"
/bin/cat $commonNameDir/cert.pem >> $commonNameDir/key.pem
/bin/cp "$commonNameDir/cert.pem" "/etc/stunnel/certs/$commonName.pem"
/bin/chmod 0664 "/etc/stunnel/certs/$commonName.pem"
/usr/bin/c_rehash /etc/stunnel/certs/
```

Stunnel configuration in `/etc/stunnel/stunnel.conf`:

```
setuid = stunnel
setgid = stunnel
pid = /var/run/stunnel/stunnel.pid

sslVersion = all

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

foreground = no

; debugging stuff (may be useful for troubleshooting)
debug = 5
output = /opt/myApp/log/stunnel.log

[CF]
client = no
accept = 1163
verify = 3
sslVersion = all
cert = /etc/stunnel/serverCert.pem
key = /etc/stunnel/serverCert.pem
CApath = /etc/stunnel/certs
TIMEOUTbusy = 60
TIMEOUTclose = 0
TIMEOUTconnect = 60
TIMEOUTidle = 60
exec = /opt/myApp/bin/cf-server
execargs = /opt/myApp/bin/cf-server -p /opt/myApp/pipes/
;execargs = /opt/myApp/bin/cf-server -p /opt/myApp/pipes/ -l /opt/myApp/log
```

Each connection from a client creates a Unix Domain Socket in the `-p` directory, where `commonName` is used as the file name.

It accepts the following commands to initiate activity on the client:
```
CONNECT _LOCAL_PORT_ _REMOTE_DOMAIN_ _REMOTE_PORT_
eg CONNECT 3389 localhost 3389 # RDP Remote Desktop access

EXEC _LOCAL_PORT_ _REMOTE_COMMAND_TO_EXECUTE_
EXEC 0 cmd /C dir /l /b /ad "C:\Program Files\"

FILE _LOCAL_PORT_ _SOURCE_OR_DEST_TO_TRANSFER_
FILE 0 c:\tmp.txt # if file c:\tmp.txt exists, transfer to server, else transfer to client and create it
```

For the above commands, the `0` means to randomly pick a local port to use for sending and receiving data. Alternatively, specify a port.
The server opens a socket for listening that the invoker is responsible to open and interact with.
The response to the command includes the local port on the server opened for listening to interact with the client and send/receive data.

The `CONNECT` and `EXEC` support bidirectional data transfer if the remote command or forwarded network connection supports such.

For `EXEC` the socket sends/receives STDIN/STDOUT to/from the running executable on the client.

For `CONNECT` the socket sends/receives data to/from the final endpoint.

For `FILE` the behavior is the following:

1. It never overwrites a file on the client.
2. If the specified file exists on the client, it sets up a transfer to the server (a "download") on a socket using the port the command response specified, which the invoker is responsible for.
3. Otherwise, it creates the file and data transmitted from the server to the client is added to the file ("upload"), via a socket on the port like the above item.
4. The invoker is expected to know and code for this remote client behavior.

These commands are also available:

```
STATUS - list of all open connections for CONNECT/EXEC/FILE operations
CLOSE - controlled shutdown of connection, including all open connections
```

### Examples of Usage

See examples of command invocation, parsing the command response, and interacting with the command and data sockets in the `bin/` and `perl/` directories.

`cfpipe` is a BASH script that simplifies using `cuttlefish` from the command line. It depends on `socat`, which is available in most distros.

Remotely execute a command. STDOUT is returned.
`cfcmd /opt/myApp/pipes/$commonName "net start"`
`cfcmd /opt/myApp/pipes/$commonName 'cmd /C dir /-C'`

Remotely execute a command shell (or another program) and run it interactively through STDIO.
`cfcmdshell /opt/myApp/pipes/$commonName`

Upload a file.
`cfcpup $commonName "/path/to/local/file.txt" "c:\\path\\to\\remote\\file.txt"`

Download a file.
`cfcpdown $commonName "c:\\path\\to\\remote\\file.txt" > "/path/to/local/file.txt"`

#### Building SSL library

Needs OpenSSL or WolfSSL (formerly CyaSSL); to cross-compile OpenSSL for Windows:

./Configure --cross-compile-prefix=i686-w64-mingw32- -DOPENSSL_NO_CAPIENG mingw no-shared
./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64
make
i686-w64-mingw32-strip -g lib*.a

make distclean
./configure --host=i686-w64-mingw32 --enable-static --enable-opensslExtra LDFLAGS="-lws2_32" CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes
make
i686-w64-mingw32-strip -g lib*.a

libcrypto.a and libssl.a are static; libeay32.a and libssl32.a are dynamic

#### Building the Client

Cross-compile on Linux:
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static -I /opt/cmf/src/cf/include cf-client-win.c XGetopt.c -o Cuttlefish.exe -L /opt/cmf/src/cf/lib -lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32 -Wl,--subsystem,console
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static                            cf-client-win.c XGetopt.c -o Cuttlefish.exe -lssl -lcrypto -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32 -static-libgcc -shared -Wl,--subsystem,console

##### With CYASSL (similar for WolfSSL)
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static -I /opt/cmf/src/cf/include cf-client-win.c -o Cuttlefish.exe -L /opt/cmf/src/cf/lib -lssl -lcrypto -lws2_32 -lntdll -lgdi32 -Wl,-verbose,--subsystem,native,-e,_NtProcessStartup@4
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static -I /opt/cmf/src/cf/include -I ./cyassl-2.0.8 -DCF_CYASSL cf-client-win.c XGetopt.c -o Cuttlefish.exe -L /opt/cmf/src/cf/cyassl-2.0.8/src/.libs -lcyassl -lws2_32 -lgdi32 -Wl,-verbose,--subsystem,console

Compile on Windows:
gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static -I C:\openssl-1.1.1g-win32-mingw\include cf-client-win.c XGetopt.c -o Cuttlefish.exe -L C:\openssl-1.1.1g-win32-mingw\lib -lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32 -static-libgcc -shared -Wl,--subsystem,console
gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -s -static -I /c/openssl-1.1.1g-win32-mingw/include cf-client-win.c XGetopt.c -o Cuttlefish.exe -L /c/openssl-1.1.1g-win32-mingw/lib -lssl -lcrypto -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32 -Wl,--subsystem,console

### Building the Server

gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os cf-server.c -o cf-server
gcc -static -m32 -Wall -Wextra -pedantic -std=gnu99 -Werror -Os cf-server.c -o cf-server32
