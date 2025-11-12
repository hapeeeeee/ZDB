cd build
pwd
cmake .. -DCMAKE_TOOLCHAIN_FILE=../../third-party/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build .