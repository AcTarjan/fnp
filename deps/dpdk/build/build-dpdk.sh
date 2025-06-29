CURRENT_DIR=$(pwd)
echo "current dir: $CURRENT_DIR"
echo "start build dpdk..."

INSTALL_DIR=${dirname $CURRENT_DIR}

cd ./dpdk-stable-22.11.8
meson setup --prefix=INSTALL_DIR build

cd ./build
ninja -j8

ninja install

echo "build dpdk successfully"
