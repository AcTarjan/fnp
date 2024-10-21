#!/bin/bash

# 初始文件大小
size=1
test_count=4
round_count=8

if [ $# -eq 2 ]; then
  test_count=$1
  round_count=$2
fi

echo "**********AUTO TEST start with: $test_count tests, $round_count rounds ********"

# 运行10次测试
for i in $(seq 1 $test_count); do
  # 创建随机文件
  ./create-randfile.sh $size

  # 运行测试脚本
  for j in $(seq 1 $round_count); do
    echo "Test $i with file size $size KB, round $j"
    ./send2dpdk.sh
    mv output/nc.dat output/nc-$j.dat
  done

  # 记录测试结果
  echo "Test $i with file size $size KB, round $j finished. Check md5sum..."
  ./check-md5.sh

  # 修改文件大小
  size=$((size * 10))
done

echo "**********AUTO TEST END************"
