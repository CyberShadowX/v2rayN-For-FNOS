# Private SQLite compatibility library

`e_sqlite3.so` is the unmodified amd64 SQLite shared library from Debian 12's
`libsqlite3-0` package, version `3.40.1-2+deb12u2`. Its upstream SQLite version
is `3.40.1`. The binary was copied from the installed NAS library and matched
byte for byte against `usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6` in the
[Debian package](https://deb.debian.org/debian/pool/main/s/sqlite3/libsqlite3-0_3.40.1-2+deb12u2_amd64.deb).
Exact package and library hashes are recorded in `SOURCE.json`.

The pinned library is copied into each staged v2rayN release directory as
`e_sqlite3.so`. This name is checked by the application's native loader before
its upstream `libe_sqlite3.so`. The original upstream files are preserved.
No system SQLite installation or glibc file is changed.

SQLite's deliverable code is dedicated to the public domain by its authors;
see [SQLite's copyright notice](https://www.sqlite.org/copyright.html).
`COPYRIGHT.debian` reproduces the exact package's copyright metadata. That
metadata separately identifies Debian packaging files under GPL-2+; those
packaging scripts are not included in this private library payload.

This adaptation addresses the observed native-library GLIBC requirement on
the target NAS. It does not guarantee every SQLite feature expected by future
v2rayN releases. Candidate GUI/database health must pass before an update is
accepted; failed candidates must use the shared updater's rollback path.
