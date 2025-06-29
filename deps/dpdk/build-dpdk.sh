CURRENT_DIR=$(pwd)
echo "current dir: $CURRENT_DIR"
echo "start build dpdk..."

#INSTALL_DIR=${dirname $CURRENT_DIR}

tar -xf dpdk-22.11.8.tar.xz
cd ./dpdk-stable-22.11.8
meson setup --prefix=$CURRENT_DIR build

cd ./build
ninja -j8

ninja install

echo "build dpdk successfully"
