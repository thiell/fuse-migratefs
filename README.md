fuse-migratefs
===========

fuse-migratefs is a FUSE implementation of a special overlay filesystem designed merge several
filesystems and disable new writes to (old) lower filesystem(s) to allow a seamless migration
to a (new) upper filesystem.
It aims to be temporarily used on automatically purged cluster "scratch" filesystems.  In this
implementation, metadata changes like renames or file permission changes are still done in the
lower layers, because in our case (Stanford Research Computing Center), we purge on file
content change (based on timestamps of Lustre's data_version kept in Robinhood).
fuse-migratefs is heavily based on fuse-overlayfs, an implementation of overlay+shiftfs in FUSE
for rootless containers.

Limitations:
=======================================================

Read-only mode is not supported.

Usage:
=======================================================

```
$ migratefs -o lowerdir=/oldscratch,upperdir=/newscratch scratch
```

Build Requirements:
=======================================================

This links to libfuse > v3
