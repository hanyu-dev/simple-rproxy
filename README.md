# Simple-RProxy

`nginx` stream proxy cannot preserve TLS fingerprint infos, so I wrote this simple reverse proxy.

## Build

You have to configure a C compiler when you develop within Windows platform.

Since io zero copy only works on unix platform, this project is actually not supported on Windows.
