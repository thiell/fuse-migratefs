# migratefs

_`migratefs` is a filesystem overlay for transparent, distributed migration of
active data across separate storage systems._


> This project started as a fork of
[`fuse-overlayfs`](https://github.com/containers/fuse-overlayfs), an
implementation of `overlay+shiftfs` in `FUSE` for rootless containers, but the
project has significantly diverged since then, and operates on very different


## About

`migratefs` is a FUSE-based filesystem overlay which presents a stacked view of
multiple, separate filesystems, and allow migration of data from the lower
layers to the upper one.

It has been designed to:
* merge the contents of several filesystems (layers),
* allow filesystem reads on all layers,
* direct filesystem writes to the upper layer,
* automatically transfer modified data from lower layers to the upper layer
  (_copyup_)

`migratefs` allows seamless migration of active files from the lower layers to
the upper level, by copying them up as they're modified. Files that are not
modified can be read from any layer, and when the same file exist in multiple
layers, the version in the highest layer is presented to applications.

It is of particular interest to migrate data between network filesystems that
are mounted on the same set of clients, but can also be used locally.

## Rationale

### Data storage lifecycle

In scientific computing environments, a substantial numbers of users typically
work on large-scale HPC clusters and store their data on parallel, distributed
filesystems. Those filesystems have a life time of several years, but aging
hardware needs to be replaced at some point, and as technology evolves, storage
density and performance increases, and user needs evolve.

*And when storage systems are replaced, data needs to be migrated.*

### Traditional data migration methods

There are a few typical scenarios that are generally adopted when time comes to
retire an older storage system and replace it by a new one:

-  **copy all the data**

    This is long and expensive process on filesystems that can span several
    petabytes and contain hundreds of millions of inodes, if not billions.  It
    can be done in either one long offline pass, or with several successive
    passes of highly-tuned, distributed copy processes, each operating on a
    fraction of the filesystem, while the filesystem remains online ; and a
    final, shorter offline synchronization pass to copy over the remaining
    differences since the last copy. It's a fastidious operation, still
    require a significant downtime where users can't work, and it will likely
    bring over old files that are not really used anymore on the new
    filesystem.


* **let users move their own data**

    Another natural approach is to bring up both filesystems side by side, and
    provide a new mountpoint that userscan use. They will then need to handle
    copying their own data, will need to change their scripts and applications
    to point to the newer mountpoint, which could be pretty disruptive to their
    workflows.

* **filesystem-specific approaches**

    Some filesystems, such as Lustre, offer internal migration tools that could
    help adding new hardware to an existing storage system, transferring the
    data from existing equipment to newly added hardware, and then retiring the
    older storage components.  This is usually a complex process, quite
    error-prone, which also require prolonged downtimes, and has some
    limitations.

`migratefs` helps solve the filesystem data migration problem by letting
storage administrators enable a transparent overlay on top of their existing
filesystems, that bridges both the old and the new storage systems, and makes
every single `write()` operation on existing files participate in the migration
of the active dataset, completely transparently for the users.

## Description

> `migratefs` only migrates actively used data, is completely transparent to the
users, and doesn't require any downtime.

The purpose of `migratefs` is to provide a way to migrate active data across
filesystems with minimal user impact. As far as users are concerned, files stay
in the same place, they can be accessed with the same paths during the
migration, and while their data is transparently migrated to another physical
storage system.

| approach | only transfers active data | transparent for users | can be done online |
| -------- | -------------------------- | -------------- | ------------------ |
| sysadmins copy all the data | :no_entry_sign: | :heavy_check_mark: | :no_entry_sign: |
| users copy their own data | :heavy_check_mark:| :no_entry_sign:    | :heavy_check_mark: |
| `migratefs` | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |


### A temporary overlay

`migratefs` is designed to be used temporarily, over a period of time during
which data will be migrated between filesystems. When the migration is done,
the `migratefs` layer can be removed and normal filesystem operations can be
resumed.

It works best on automatically purged filesystem. Many computing centers define
purge policies on their large filesystems, that automatically delete files
based on their age, access patterns, etc. Enabling `migratefs` over purged
filesystems makes it easier to define the migration period, as files that are
actively used will be carried over to the new filesystem, while the files that
sit idle will progressively be removed by the existing purge policies. In the
end, all the new data will have been moved over to the new filesystem, and the
old filesystem will be empty, so it could be retired and decommissioned.

Direct access to the underlying filesystem layers is always possible, although
in case of a data migration, it's better to keep the lower levels unmodified.
But new files can be written and read directly from the upper layer without any
impact on `migratefs` functioning.


#### Migration timeline

The typical timeline for a data migration with `migratefs` looks like this:

* **Step 0**: the historical storage system is mounted under `/scratch`

* **Step 1**: a short downtime permits to:
  * remount `/scratch` as `/old`
  * mount the new filesystem under `/new`
  * start `migratefs` to aggregate both under `/scratch`

* **Step 2**: user activity resumes:
  * data is transparently migrated from `/old` to `/new` while user access
    their files under `/scratch`
  * `/new`, initially empty, starts to receive newly written files, and
    copy-up'ed files form `/old`.
  * `/old` continue to be purged by the existing purge policies, and start to
    empty out.

* **Step 3**: when `/old` is empty or the migration deadline has been reached,
  a final downtime allows to:
  * stop `migratefs`
  * retire `/old`
  * remount `/new` as `/scratch`

Once the migration is over, users continue to use `/scratch` as before, except
now, all their files are on the new filesystem and the old one has been
retired.

## Features

### High-level

* allows migrating data between completely separate filesystems, using
  different hardware components, different technologies, and even of different
  types (GPFS to Lustre, BeeGFS to NFS, or even locally between local
  filesystems)
* only migrates data that users actively modify, so you won't end up with
  old, dead files that nobody uses anymore on your brand new filesystem
* distributes the data migration across all the hosts that access the
  filesystem
* completely transparent for the end users, they don't even need to know
  abouit `migratefs`


### In practice

* node-local overlay filesystem in user space
* merge multiple directories/filesystems (layers) and seamlessly migrate data
  to upper layer when needed
* dispatch I/O syscalls to the right underlying layer
* multi-threaded
* works better on network filesystems
* easy to use and deploy (one process to run)


## Usage

### Requirements

`migratefs` requires [`libfuse`](https://github.com/libfuse/libfuse) 3.x.

### Installation

```
$ configure
$ make
```
A SPEC file is provided to build a RPM, as well as a Docker file

### Run

```
$ migratefs -o lowerdir=/oldscratch,upperdir=/newscratch /scratch
```

### Limitations

* Read-only mode is not supported.

* Umask has precedence over Default POSIX ACLs.

* fgetxattr/fsetxattr (get/set extended attributes) of an unlinked file is not supported.

* Performance is lower than directly accessing the underlying layers



