# migratefs

[![Build Status](https://travis-ci.org/stanford-rc/fuse-migratefs.svg?branch=master)](https://travis-ci.org/stanford-rc/fuse-migratefs)

_`migratefs` is a filesystem overlay for transparent, distributed migration of
active data across separate storage systems._


> This project started as a fork of
[`fuse-overlayfs`](https://github.com/containers/fuse-overlayfs), an
implementation of `overlay+shiftfs` in `FUSE` for rootless containers, but the
project has significantly diverged since then, and operates on very different
premises.


## About

`migratefs` is a FUSE-based filesystem overlay designed to semalessly migrate
data from one filesystem to another. It aggregates multiple, separate
filesystems or directories, to present a stacked view of their contents and
allows migration of modified data from the lower to the upper layer.

<img align="center" src="https://docs.google.com/drawings/d/e/2PACX-1vT0p9txFKOVS9GazuZFIfolJp0ksmlXNlb0MsjyR_F3rPNtdXEe3ho25lpW55sNKk_NHmc0WyErQnCA/pub?w=484&h=195"/>


## Table of contents

- [About](#about)
- [Description](#description)
  - [Rationale](#rationale)
  - [Use case](#use-case)
  - [Features](#features)
- [Usage](#Usage)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Configuration](#configuration)

## Description

The purpose of `migratefs` is to provide a way to migrate active data across
storage systems with minimal user impact. As far as users or applications are
concerned, files stay in the same place, they can be accessed with the same
paths during the migration, while their contents are transparently migrated
from one storage system to another.

It has been designed to:

* present a merged view of several filesystems or directories (_layers_),
* allow reads on all layers (when the same file exist in multiple layers, the
  version in the highest layer is presented to the calling application),
* re-direct writes to the upper layer,
* automatically transfer modified data from lower levels to the upper layer
  (_copyup_)

It is of particular interest to migrate data between network filesystems that
are mounted on the same set of clients, but can also be used locally.



### Rationale

#### Data storage life cycle

In scientific computing environments, a substantial numbers of users typically
work on large-scale HPC clusters and store their data on parallel, distributed
filesystems. Those filesystems have a life time of several years, but aging
hardware needs to be replaced at some point, to accommodate evolutions in storage
density, I/O performance increases and user needs.

*And when storage systems are replaced, data needs to be migrated.*

#### Traditional data migration methods

There are a few typical scenarios that are generally adopted when time comes to
retire an older storage system and replace it by a new one:


* _copy all the data_

    > This is long and expensive process on filesystems that can span several
    petabytes and contain hundreds of millions of inodes, if not billions.  It
    can be done in either one long offline pass, or with several successive
    passes of highly-tuned, distributed copy processes, each operating on a
    fraction of the filesystem, while the filesystem remains online ; and a
    final, shorter offline synchronization pass to copy over the remaining
    differences since the last copy. It's a fastidious operation, still require
    a significant downtime where users can't work, and it will likely bring
    over old files that are not really used anymore on the new filesystem.


* _let users move their own data_

    > Another natural approach is to bring up both filesystems side by side,
    and provide a new mountpoint that users can use. They will then need to
    handle copying their own data, will need to change their scripts and
    applications to point to the newer mountpoint, which could be pretty
    disruptive to their workflows.

* _filesystem-specific tools_

    > Some filesystems, such as Lustre, offer internal migration tools that
    could help adding new hardware to an existing storage system, transferring
    the data from existing equipment to newly added hardware, and then retiring
    the older storage components.  This is usually a complex process, quite
    error-prone, which also require prolonged downtimes, and has some
    limitations.


`migratefs` helps solve the filesystem data migration problem by letting
storage administrators enable a transparent overlay on top of their existing
filesystems, that bridges both the old and the new storage systems, and makes
every single `write()` operation on existing files participate in the migration
of the active dataset, completely transparently for the users.

`migratefs` only **migrates actively used data**, is **completely transparent to
users and application**, and **doesn't require any extended downtime.**

| Method | copy all the data | users move their files | `migratefs` |
| ------ | ----------------- | --------------------- | ----------- |
| ignore inactive data | :no_entry:  | :heavy_check_mark: | :heavy_check_mark: |
| transparent for users    | :no_entry:  | :no_entry:  | :heavy_check_mark: |
| can be done online       | :no_entry:  | :heavy_check_mark: | :heavy_check_mark: |
| distributed data transfers | possible  | possible | :heavy_check_mark: |


### Use case

`migratefs` has been developed to solve the typical case of a HPC center
needing to retire a shared, automatically purged `/scratch` filesystem, and
move all of its actively-used data to a new storage system.

> Many computing centers define purge policies on their large filesystems, that
automatically delete files based on their age, access patterns, etc. Enabling
`migratefs` over purged filesystems makes it easier to define the migration
period, as files that are actively used will be transferred over to the new
filesystem, while the files that sit idle will progressively be removed by the
existing purge policies. In the end, all the new data will have been moved over
to the new filesystem, and the old filesystem will be empty, so it could be
retired and decommissioned.

`migratefs` is designed to be used temporarily, over a period of time during
which data will be migrated between filesystems. When the migration is done,
the `migratefs` layer can be removed and normal filesystem operations can be
resumed.

Direct access to the underlying filesystem layers is always possible, although
in case of a data migration, it's better to keep the lower levels unmodified.
But new files can be written and read directly from the upper layer without any
impact on `migratefs` functioning.


#### Migration timeline

Let's say you have a `/scratch` filesystem that needs to be retired, and you
have a new filesystem ready to replace it already. The typical timeline for a
data migration with `migratefs` would look like this:

* **Step 1**: during a short scheduled downtime, storage admins:
  * remount `/scratch` as `/scratch_old`
  * mount the new filesystem under `/scratch_new`
  * start `migratefs` to aggregate both filesystems under `/scratch`

* **Step 2**: user activity resumes:
  * data is transparently migrated from `/scratch_old` to `/scratch_new` while
    user access their files in `/scratch`
  * `/scratch_new`, initially empty, starts to receive newly written files, and
    copy-up'ed files form `/scratch_old`.
  * `/scratch_old` continues to be purged by the existing purge policies, and
    starts to empty out.

* **Step 3**: when `/old` is empty or when the migration deadline has been
  reached, a final downtime allows to:
  * stop `migratefs`
  * retire `/scratch_old`
  * remount `/scratch_new` as `/scratch`

Once the migration is over, users continue to use `/scratch` as before, except
now, all their files are on the new filesystem and the old one has been
retired.

<img align="center"
src="https://docs.google.com/drawings/d/e/2PACX-1vT0i3mCSl-22U8e-hu3uNH81AN2vH-jgwUnsgBUU1Wc41Quv8x-00DH52zyA6j4D8o1TGVibdEwwjuF/pub?w=981&h=561"/>

During the migration period:
* all of the newly created files will be physically stored on the new
  filesystem,
* all the existing files that have been accessed will be migrated to the new
  system,
* the purge policies running on the old system will progressively delete the
  files that are not accessed, and empty it out.

In the end, all the active data will be on `/scratch_new`, and `/scratch_old`
will be empty. All the active data would have then been migrated in a
completely distributed way as each client would have participated to the
migration, the old system could be retired, and the new system would be ready
to use natively, without any old data lingering around.




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
  about `migratefs`


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

A specfile for CentOS 7 can be found [here](https://github.com/stanford-rc/fuse3-centos7).

### Installation

```
$ ./autogen.sh
$ ./configure
$ make
```

To build a RPM:
```
$ make rpm
```

### Execution

```
$ migratefs -o lowerdir=/oldscratch,upperdir=/newscratch /scratch
```

#### Options

TBW

### Limitations

TBW
* Read-only mode is not supported.

* Umask has precedence over Default POSIX ACLs.

* fgetxattr/fsetxattr (get/set extended attributes) of an unlinked file is not supported.

* Performance is lower than directly accessing the underlying layers



