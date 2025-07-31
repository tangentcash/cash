FROM alpine:latest AS build
ARG CONFIGURE=""
ARG COMPILE="-j"
RUN echo "ipv6" >> /etc/modules
RUN apk update && apk upgrade && apk update
RUN apk add clang clang-dev alpine-sdk dpkg mold ninja cmake
RUN ls -l /usr/bin/cc /usr/bin/c++ /usr/bin/clang /usr/bin/clang++ && ln -sf /usr/bin/clang /usr/bin/cc && ln -sf /usr/bin/clang++ /usr/bin/c++
RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang 10 && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 10
RUN update-alternatives --auto cc && update-alternatives --auto c++ && update-alternatives --display cc && update-alternatives --display c++
RUN ls -l /usr/bin/cc /usr/bin/c++
RUN mkdir /home/tangentcash && mkdir /home/tangentcash/make
RUN apk add libsecp256k1-dev gmp-dev protobuf-dev libsodium-dev rocksdb-dev sqlite-dev openssl-dev zlib-dev libunwind-dev elfutils-dev
COPY ./ /home/tangentcash/source/
WORKDIR /home/tangentcash/source
RUN cmake -G Ninja -S=/home/tangentcash/source -B=/home/tangentcash/make $CONFIGURE -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/usr/local/bin -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=/usr/local/lib
RUN cmake --build /home/tangentcash/make $COMPILE
RUN rm -r /home/tangentcash

FROM alpine:latest AS deployment
RUN apk add libsecp256k1-dev gmp-dev protobuf-dev libsodium-dev rocksdb-dev sqlite-dev openssl-dev zlib-dev libunwind-dev elfutils-dev
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /usr/local/lib /usr/local/lib
WORKDIR /usr/local/bin
ENV PATH="${PATH}:/usr/local/lib"