# Image Hash Spoofing Tool

## Overview
A cryptographic tool that modifies images to generate a hash with a specific prefix while maintaining visual integrity.

## Features
- SHA-512 hash manipulation
- Minimal image modification
- Cross-platform compatibility

## Dependencies
- OpenSSL
- ImageMagick
- CMake (for building)
- Unity Test Framework (for testing)

## Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev libmagickcore-dev libmagickwand-dev cmake

# macOS (with Homebrew)
brew install openssl imagemagick cmake
```

### Build
```bash
mkdir build
cd build
cmake ..
make
```

## Usage
```bash
# Generate an image with a hash starting with '24'
./spoof 24 input.jpg output.jpg
```

## Testing
```bash
# Run test suite
./test_spoof
```

## License
MIT License