# Getting Started

This guide will help you set up and run your first patched Frida build.

## Prerequisites

### Required

- **Docker**: Version 20.10 or later
  ```bash
  docker --version
  ```

- **Git**: For creating and managing patches
  ```bash
  git --version
  ```

### Recommended

- 8GB+ RAM for building
- 20GB+ free disk space
- Fast internet connection (downloads ~2GB of sources)

## Installation

1. Clone or copy this framework to your machine:
   ```bash
   git clone <repository-url> frida-patch-testing
   cd frida-patch-testing
   ```

2. Create your configuration:
   ```bash
   cp config.default.yaml config.yaml
   ```

## Your First Build

### Building Vanilla Frida

To verify your setup works, build Frida without any patches:

1. Ensure no patches exist:
   ```bash
   ls patches/frida-*/
   # Should only show .gitkeep files
   ```

2. Run the build:
   ```bash
   ./build/run.sh
   ```

3. Check the output:
   ```bash
   ls output/
   # Should contain frida-server
   ```

### Building with a Patch

1. Add a patch file to the appropriate directory:
   ```bash
   cp /path/to/your/patch.patch patches/frida-gum/0001-my-patch.patch
   ```

2. Run the build:
   ```bash
   ./build/run.sh
   ```

The build script will:
1. Clone Frida source
2. Apply your patches
3. Build the configured targets
4. Copy artifacts to `output/`

## Next Steps

- [Creating Patches](creating-patches.md)
- [Configuration Reference](configuration.md)
- [Using Custom Repositories](using-custom-repos.md)
