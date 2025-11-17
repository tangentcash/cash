
## Build: As a Docker image
Executable named _tangentcash_ will be installed to following paths:
```sh
/usr/local/bin
/usr/local/lib
```

Clone this repository recursively
```bash
git clone https://github.com/tangentcash/cash --recursive
```

To customize your build you may use following docker build-arg arguments:
```sh
$CONFIGURE # CMake configuration arguments
$COMPILE   # Compiler configuration arguments
```

### Image: LLVM Debian
```sh
docker build -f . -t tangentcash:staging .
```