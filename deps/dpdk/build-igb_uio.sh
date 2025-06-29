# 编译igb_uio
git clone http://dpdk.org/git/dpdk-kmods
cd dpdk-kmods/linux/igb_uio
make -j8

# 安装igb_uio到内核
sudo modprobe uio        # 先加载uio框架
sudo insmod igb_uio.ko   # 加载igb_uio

# igb_uio模块开机自动加载
#sudo cp igb_uio.ko /lib/modules/$(uname -r)/kernel/drivers/uio/
#echo "igb_uio" | sudo tee /etc/modules-load.d/igb_uio.conf