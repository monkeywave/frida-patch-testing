# Frida Patch Testing Framework

A Docker-based environment for testing custom patches and forks of Frida before
submitting upstream or for private builds.

## Features

- **Always Latest**: Builds from the latest Frida source by default
- **Patch Support**: Apply custom patches to any Frida component
- **Fork Support**: Use your own repository forks instead of official repos
- **Mix & Match**: Combine patches for some components, forks for others
- **Reproducible**: Docker-based builds ensure consistent results
- **Examples**: Includes working examples like the child-gating fix

## Quick Start

### Prerequisites

- Docker installed and running
- Git (for creating patches)

### Option 1: Build with Patches

1. Clone this repository
2. Add your patch files to `patches/<component>/`:
   ```
   patches/
   ├── frida-gum/
   │   └── 0001-my-fix.patch
   └── frida-core/
       └── 0001-another-fix.patch
   ```
3. Run the build:
   ```bash
   ./build/run.sh
   ```
4. Find your built binaries in `output/`

### Option 2: Build from Custom Fork

1. Edit `config.yaml`:
   ```yaml
   components:
     frida-gum:
       source: "custom"
       repository: "https://github.com/YOUR_USER/frida-gum"
       branch: "my-feature-branch"
   ```
2. Run the build:
   ```bash
   ./build/run.sh
   ```

### Option 3: Use Included Example

```bash
# Copy example configuration
cp examples/child-gating-fix/config.yaml config.yaml

# Copy example patches
cp -r examples/child-gating-fix/patches/* patches/

# Build
./build/run.sh
```

## Directory Structure

```
frida-patch-testing/
├── config.yaml              # Your configuration (create from default)
├── config.default.yaml      # Default configuration
├── config.example.yaml      # Documented example
│
├── build/
│   ├── Dockerfile           # Build environment
│   ├── build.sh             # Main build script
│   ├── run.sh               # Host launcher
│   └── scripts/             # Helper scripts
│
├── patches/
│   ├── templates/           # Patch templates
│   ├── frida-gum/           # Patches for frida-gum
│   ├── frida-core/          # Patches for frida-core
│   ├── frida-python/        # Patches for frida-python
│   └── frida-tools/         # Patches for frida-tools
│
├── examples/
│   └── child-gating-fix/    # Working example
│
├── docs/                    # Additional documentation
└── output/                  # Build outputs
```

## Configuration

See [docs/configuration.md](docs/configuration.md) for full reference.

### Basic Structure

```yaml
frida:
  version: "latest"  # or specific tag like "16.5.2"

components:
  frida-gum:
    source: "official"  # or "custom"
    patches: true       # apply patches from patches/frida-gum/
    # For custom source:
    # repository: "https://github.com/user/frida-gum"
    # branch: "main"

build:
  targets:
    - frida-server
  architecture: "auto"  # or "arm64", "x86_64"
```

## Creating Patches

See [docs/creating-patches.md](docs/creating-patches.md) for detailed guide.

### Quick Method

```bash
# Clone the component
git clone https://github.com/frida/frida-gum.git
cd frida-gum

# Make changes and commit
git checkout -b my-fix
# ... edit files ...
git commit -am "gum: fix something important"

# Generate patch
git format-patch -1 HEAD
# Move to patches directory
mv 0001-*.patch /path/to/patches/frida-gum/
```

## Examples

### child-gating-fix

Fixes process freezes when using child-gating on Linux. See
[examples/child-gating-fix/README.md](examples/child-gating-fix/README.md).

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for common issues.

## License

This framework is released under the wxWindows Library Licence, the same
license used by Frida itself.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Add your changes
4. Submit a pull request

For patches to Frida itself, please submit upstream to the official repositories.
