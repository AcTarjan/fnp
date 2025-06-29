

tar -xf picotls-src.tgz

#-S 指定CMakeLists.txt所在目录
# -B 指定构建目录
# -DCMAKE_INSTALL_PREFIX指定安装路径
cd picotls-src
rm -rf ./build
mkdir build && cd build

cmake ../

make -j8

cp libpicotls-* ../../../../dep_libs/picotls/lib/
cd ../
cp -r ./include ../../../dep_libs/picotls/
