#!/bin/bash
# copyup+truncate test

set -e

LOWERDIR=${LOWERDIR:-/lower}
UPPERDIR=${UPPERDIR:-/upper}
MOUNTPOINT=${MOUNTPOINT:-/merged}

rm -rf $MOUNTPOINT/a

# create file in lower
mkdir -p $LOWERDIR/a/b/c
dd if=/dev/urandom of=$LOWERDIR/a/b/c/src bs=256k count=100 conv=fsync
dd if=/dev/urandom of=$LOWERDIR/a/b/c/tgt bs=256k count=100 conv=fsync
chksum_lo=($(md5sum $LOWERDIR/a/b/c/src))
stat $LOWERDIR/a/b/c/src
stat $LOWERDIR/a/b/c/tgt
chown -R $USER $LOWERDIR/a

# set xattr
setfacl -m u:$USER:rwx $LOWERDIR/a/b/c/tgt

# perform copyup(truncate) from unpriviledged user
sudo -u $USER cp $MOUNTPOINT/a/b/c/src $MOUNTPOINT/a/b/c/tgt
stat $UPPERDIR/a/b/c/tgt
chksum_up=($(md5sum $UPPERDIR/a/b/c/tgt))
[[ $chksum_lo == $chksum_up ]] && echo copyup+truncate success
