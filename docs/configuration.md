# Configuration Reference

Complete reference for `config.yaml` options.

## File Structure

```yaml
frida:
  version: string
  repository: string

components:
  <component-name>:
    source: "official" | "custom"
    patches: boolean
    repository: string  # when source is "custom"
    branch: string      # optional

build:
  targets: string[]
  architecture: "auto" | "arm64" | "x86_64"
  debug: boolean

output:
  directory: string
  artifacts: string[]
```

## Frida Section

### version

The Frida version to build.

- `"latest"` - Clone default branch (recommended)
- `"16.5.2"` - Specific release tag

### repository

Base Frida repository URL. Usually don't change this.

Default: `"https://github.com/frida/frida.git"`

## Components Section

Configure each Frida component individually.

### Available Components

- `frida-gum` - Core instrumentation engine
- `frida-core` - Frida server and client
- `frida-python` - Python bindings
- `frida-tools` - CLI tools (frida, frida-ps, etc.)

### Component Options

#### source

Where to get the component source:
- `"official"` - Use official submodule (default)
- `"custom"` - Use custom repository

#### patches

Whether to apply patches from `patches/<component>/`:
- `true` - Apply all .patch files (default)
- `false` - Skip patches

Only used when `source: "official"`.

#### repository

Custom repository URL. Required when `source: "custom"`.

```yaml
frida-gum:
  source: "custom"
  repository: "https://github.com/myuser/frida-gum"
```

#### branch

Branch to checkout. Optional, defaults to main/master.

```yaml
frida-gum:
  source: "custom"
  repository: "https://github.com/myuser/frida-gum"
  branch: "my-feature"
```

## Build Section

### targets

List of build targets:
- `frida-server` - Server binary
- `frida-python` - Python module
- `frida-tools` - CLI tools

### architecture

Target architecture:
- `"auto"` - Detect from host (default)
- `"arm64"` - Build for ARM64
- `"x86_64"` - Build for x86_64

### debug

Enable debug symbols:
- `true` - Include debug info
- `false` - Release build (default)

## Output Section

### directory

Output directory for artifacts. Default: `"./output"`

### artifacts

List of artifacts to copy to output directory.

## Example Configurations

### Minimal (defaults)

```yaml
frida:
  version: "latest"
```

### With Custom Fork

```yaml
frida:
  version: "latest"

components:
  frida-gum:
    source: "custom"
    repository: "https://github.com/myuser/frida-gum"
    branch: "my-fixes"
```

### Debug Build

```yaml
frida:
  version: "16.5.2"

build:
  targets:
    - frida-server
  debug: true
```
