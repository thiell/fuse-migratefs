#!/bin/bash
# copyup test

set -e

LOWERDIR=${LOWERDIR:-/lower}
UPPERDIR=${UPPERDIR:-/upper}
MOUNTPOINT=${MOUNTPOINT:-/merged}

rm -rf $MOUNTPOINT/a

# create file in lower
mkdir -p $LOWERDIR/a/b/c
dd if=/dev/urandom of=$LOWERDIR/a/b/c/file bs=256k count=100 conv=fsync
chksum_lo=($(md5sum $LOWERDIR/a/b/c/file))
stat $LOWERDIR/a/b/c/file
chown -R $USER $LOWERDIR/a

# create file tree
rm -rf $MOUNTPOINT/tree
mkdir $MOUNTPOINT/tree
chmod 700 $MOUNTPOINT/tree
cd $MOUNTPOINT/tree
wget -q https://mirrors.edge.kernel.org/pub/linux/kernel/v1.0/linux-1.0.tar.xz
tar xf linux-1.0.tar.xz

# run 10 find in background as root
cd $MOUNTPOINT
for i in {1..10}; do
    find -ls >/dev/null &
    pids[${i}]=$!
done

# perform copyup from unpriviledged user
sudo -u $USER touch $MOUNTPOINT/a/b/c/file
stat $UPPERDIR/a/b/c/file
chksum_up=($(md5sum $UPPERDIR/a/b/c/file))
[[ $chksum_lo == $chksum_up ]] && echo copyup success

# check if the find commands all succeeded during copyup
rc=0
for pid in ${pids[*]}; do
    wait $pid
    rc=$(( $? > $rc ? $? : $rc ))  
done
exit $rc
