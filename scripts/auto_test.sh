#!/bin/bash

# 初始文件大小
size=1
test_count=3
round_count=20

if [ $# -eq 2 ]; then
  test_count=$1
  round_count=$2
fi

echo "**********AUTO TEST start with: $test_count tests, $round_count rounds ********"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

cd "${REPO_ROOT}"

for i in $(seq 1 $test_count); do
  "${SCRIPT_DIR}/create-randfile.sh" $size
  md5_1=$(md5sum "output/input.dat" | awk '{ print $1 }')
  echo "md5 of input.dat: $md5_1"
  for j in $(seq 1 $round_count); do
    echo "Test $i with file size $size KB, round $j"
    "${SCRIPT_DIR}/send2dpdk.sh"
    md5_2=$(md5sum "output/nc.dat" | awk '{ print $1 }')
    if [ "$md5_1" != "$md5_2" ]; then
      if [ "$md5_2" == "d41d8cd98f00b204e9800998ecf8427e" ]; then
        echo "ncat timeout!!!"
        continue
      fi
      echo "error in $i $j!!! md5 of nc.dat: $md5_2"
      mv output/nc.dat output/nc-$i-$j.dat
      exit
    fi
  done

  echo "Test $i with file size $size KB, round $j finished."
  size=$((size * 10))
done

echo "**********AUTO TEST END************"
