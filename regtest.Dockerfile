FROM alpine:latest
RUN apk add clang clang-dev ninja cmake libsecp256k1-dev gmp-dev libsodium-dev rocksdb-dev sqlite-dev openssl-dev zlib-dev libunwind-dev elfutils-dev
RUN mkdir /home/tangentcash && mkdir /home/tangentcash/make
COPY ./ /home/tangentcash/source/
WORKDIR /home/tangentcash/source
RUN cmake -G Ninja -S=/home/tangentcash/source -B=/home/tangentcash/make -DCMAKE_BUILD_TYPE=Debug -DTAN_TEST=ON -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/usr/local/bin -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=/usr/local/lib
RUN cmake --build /home/tangentcash/make -j
RUN tangentcash --test=regression --network=regtest