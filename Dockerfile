FROM alpine:latest AS build
RUN apk add clang clang-dev ninja cmake libsecp256k1-dev gmp-dev libsodium-dev rocksdb-dev sqlite-dev openssl-dev zlib-dev libunwind-dev elfutils-dev
RUN mkdir /home/tangentcash && mkdir /home/tangentcash/make
COPY ./ /home/tangentcash/source/
WORKDIR /home/tangentcash/source
ARG CONFIGURE="-DCMAKE_BUILD_TYPE=RelWithDebInfo"
RUN cmake -G Ninja -S=/home/tangentcash/source -B=/home/tangentcash/make $CONFIGURE -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/usr/local/bin -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=/usr/local/lib
ARG COMPILE="-j"
RUN cmake --build /home/tangentcash/make $COMPILE
RUN rm -r /home/tangentcash

FROM alpine:latest AS deployment
WORKDIR /usr/local/bin
ENV PATH="${PATH}:/usr/local/lib"
RUN apk add libsecp256k1-dev gmp-dev libsodium-dev rocksdb-dev sqlite-dev openssl-dev zlib-dev libunwind-dev elfutils-dev
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /usr/local/lib /usr/local/lib