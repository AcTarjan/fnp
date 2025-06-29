rm -rf ./build

mkdir build

tar -xf picotls-src.tgz

#-S 指定CMakeLists.txt所在目录
# -B 指定构建目录
# -DCMAKE_INSTALL_PREFIX指定安装路径
cmake -S ./picotls-src -B ./build

cd ./build
make -j8
