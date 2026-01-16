# Patches Directory

This directory contains patches to be applied to Frida components during the build.

## Directory Structure

```
patches/
├── frida-gum/       # Patches for frida-gum (instrumentation engine)
├── frida-core/      # Patches for frida-core (server/client)
├── frida-python/    # Patches for frida-python (Python bindings)
├── frida-tools/     # Patches for frida-tools (CLI tools)
└── templates/       # Patch templates to help you create your own
```

## Adding Patches

1. Create your patch file (see [templates/](templates/) for examples)
2. Place it in the appropriate component directory
3. Name with a numeric prefix for ordering: `0001-description.patch`

## Patch Format

Patches should be in git format-patch format:

```
From: Your Name <email@example.com>
Subject: [PATCH] component: brief description

Detailed explanation.

---
 path/to/file.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/path/to/file.c b/path/to/file.c
...
```

## Application Order

Patches are applied alphabetically by filename within each component:

```
0001-first.patch      # Applied first
0002-second.patch     # Applied second
0010-third.patch      # Applied third
```

## Creating Patches

### Quick Method

```bash
git clone https://github.com/frida/frida-gum.git
cd frida-gum
git checkout -b my-fix
# Make changes...
git commit -am "gum: fix something"
git format-patch -1 HEAD
mv 0001-*.patch /path/to/patches/frida-gum/
```

### From Templates

See the [templates/](templates/) directory for starter templates.

## Testing Patches

Before building, verify your patch applies:

```bash
git apply --check your-patch.patch
```

## Disabling Patches

To skip patches for a component, edit `config.yaml`:

```yaml
components:
  frida-gum:
    source: "official"
    patches: false  # Skip patches for this component
```

## More Information

- [Creating Patches Guide](../docs/creating-patches.md)
- [Templates README](templates/README.md)
