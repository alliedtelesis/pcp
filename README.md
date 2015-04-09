Port Control Protocol
=====================
This program is a PCP server. It implements sections of
[RFC6887](http://tools.ietf.org/html/rfc6887) as described below. The program
(pcpd) is written to run as a standalone server on any Linux system with the
following dependencies:
* libglib2.0
* protobuf-c
* Apteryx (by Allied Telesis Labs): see installation procedure

Apteryx also requires libcunit and headers to be installed.

Implementation
--------------
At the current version, pcpd only supports MAP requests without options. All
other message types are ignored.

License
-------
pcpd is licensed under the GPLv3 license. See the file COPYING for the full
text.

Installation Procedure
======================
* Download and install Apteryx from https://github.com/ATL-NZ/ (requires
  libglib2.0-dev libcunit1-dev libprotobuf-c0-dev protobuf-c-compiler)
* The pcp Makefiles expect apteryx at ../apteryx so a directory structure like
  code/apteryx and code/pcp is recommended

In the pcp directory, run
* autoreconf -i
* ./configure && make

Running pcpd
============
* Start Apteryx: ../apteryx/apteryx
* ./pcpd
* `LD_LIBRARY_PATH` might have to be adjusted to include the folders api/ and ../apteryx.

Running tests
-------------
pcpd comes with an extensive set of unit tests. They can be run using
[Novaprova](http://www.novaprova.org).
