# rm -rf build
# mkdir build
# clang -shared -o build/libdcommitt.so src/dcommitt.c \
#     -std=c17 \
#     -fPIC \
#     -I./libsodium/src/libsodium/include/sodium \
#     -I./libsodium/src/libsodium/include/sodium/private \
#     -v \
#     -Ofast # \
#     # -lm
clang-format -i src/**/*.[c,h] __tests__/**/*.[c,h] include/*.h
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -B build
cmake --build build

# # Compile test for valgrind
# clang -c -o ./build/libdcommitt_test.o __tests__/test.c \
#     -std=c17 \
#     -fPIC \
#     -I./include/dcommitt.h \
#     -I./libsodium/src/libsodium/include/sodium \
#     -I./libsodium/src/libsodium/include/sodium/private \
#     -ggdb \
#     -g3 \
#     -fstandalone-debug \
#     -Og \
#     -gdwarf-4 \
#     -fsanitize=address \
#     -fsanitize=undefined \
#     -fsanitize=float-divide-by-zero \
#     -fsanitize=float-cast-overflow \
#     -fno-sanitize-recover=all \
#     -fno-sanitize=null \
#     -fno-sanitize=alignment # \
#     # -lm

# chmod a+x ./build/libdcommitt_test.o
# ./build/libdcommitt_test.o

# clang -ggdb -g -fstandalone-debug -Og -gdwarf-4 \
#     -v \
#     -L./build \
#     -ldcommitt_test \
#     -I./include \
#     -I./libsodium/src/libsodium/include/sodium \
#     -I./libsodium/src/libsodium/include/sodium/private \
#     -o ./build/test.o \
#     ./__tests__/test.c

chmod a+x ./build/__tests__/commit_test
./build/__tests__/commit_test
# rm -rf ./build/valgrind
# mkdir ./build/valgrind
# valgrind --log-file=./build/valgrind/log.txt \
#     --leak-check=full \
#     --show-leak-kinds=all \
#     --track-origins=yes \
#     --verbose \
#     --dsymutil=yes \
#     --trace-children=yes \
#     -v \
#     ./build/__tests__/test

chmod a+x ./build/__tests__/shamir_test
./build/__tests__/shamir_test

chmod a+x ./build/__tests__/crypto_test
./build/__tests__/crypto_test

chmod a+x ./build/__tests__/merkle_test
./build/__tests__/merkle_test

source ./emsdk/emsdk_env.sh
NODE_ENV="production" node scripts/emscripten.js
# NODE_OR_BROWSER="browser" NODE_ENV="production" node scripts/emscripten.js
# NODE_OR_BROWSER="node" NODE_ENV="production" node scripts/emscripten.js
