# Tincan

Tincan is the default [evio](https://github.com/EdgeVPNio/evio) datapath and provides the capability for end-to-end tunneling of IP traffic between peer endpoints. It's fundamental abstraction is the Tincan tunnel which is build on the WebRTC data channel. Tincan supports the ongoing research into virtual overlay networks and the [Evio controller](https://github.com/EdgeVPNio/evio/tree/master/controller).

## Build
Tincan uses the generate ninja (GN) build system. It also supports multiple platform builds via cross compilation from a Debian x64 host system. You must clone the [evio](https://github.com/EdgeVPNio/evio), [external](https://github.com/EdgeVPNio/external), and [tools](https://github.com/EdgeVPNio/tools) repositories into the same base directory. See their respective README for addition information.

For a Debian x64 target run the following commands.
```
export PATH=/path/to/local/EdgeVPNio/tools/bin:$PATH
gn gen out/release --args='target_sysroot_dir="/path/to/local/EdgeVPNio/external"'
ninja -C out/release
```



## EdgeVPNio Project
For detailed guides on getting started or advanced use cases, refer to the documentation on the [EdgeVPNio website](http://edgevpn.io).
