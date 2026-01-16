# Using Custom Repositories

Guide to building Frida with your own forked repositories.

## Overview

Instead of patches, you can use complete repository forks. This is useful for:
- Large changes that don't work well as patches
- Ongoing development work
- Testing branches before merging

## Basic Usage

### 1. Fork the Repository

Fork the component on GitHub:
- https://github.com/frida/frida-gum → Your fork
- https://github.com/frida/frida-core → Your fork

### 2. Configure

Edit `config.yaml`:

```yaml
components:
  frida-gum:
    source: "custom"
    repository: "https://github.com/YOUR_USERNAME/frida-gum"
    branch: "my-feature"  # optional
```

### 3. Build

```bash
./build/run.sh
```

## Configuration Examples

### Single Custom Component

```yaml
components:
  frida-gum:
    source: "custom"
    repository: "https://github.com/myuser/frida-gum"
    branch: "fork-safe-interceptor"

  frida-core:
    source: "official"
    patches: true
```

### Multiple Custom Components

```yaml
components:
  frida-gum:
    source: "custom"
    repository: "https://github.com/myuser/frida-gum"
    branch: "my-gum-changes"

  frida-core:
    source: "custom"
    repository: "https://github.com/myuser/frida-core"
    branch: "my-core-changes"
```

### Mixed: Custom + Patches

```yaml
components:
  frida-gum:
    source: "custom"
    repository: "https://github.com/myuser/frida-gum"

  frida-core:
    source: "official"
    patches: true  # Apply patches from patches/frida-core/
```

## Keeping Your Fork Updated

### Sync with Upstream

```bash
cd your-frida-gum-fork

# Add upstream remote (once)
git remote add upstream https://github.com/frida/frida-gum.git

# Fetch upstream changes
git fetch upstream

# Merge into your branch
git checkout my-feature
git merge upstream/main

# Push to your fork
git push origin my-feature
```

### Dealing with Conflicts

When upstream changes conflict with your modifications:

1. Merge upstream into your branch
2. Resolve conflicts
3. Test the build
4. Push updated branch

## Branch Strategy

### For Features

```
main (tracks upstream) → feature-branch → PR to upstream
```

### For Long-term Forks

```
upstream/main → your-main (stable) → feature branches
```

## Tips

### Use SSH URLs

For private repos or to avoid authentication prompts:

```yaml
repository: "git@github.com:myuser/frida-gum.git"
```

### Pin to Commits

For reproducible builds, use a specific commit:

```bash
# In your fork
git checkout specific-commit
git checkout -b stable-v1
git push origin stable-v1
```

```yaml
branch: "stable-v1"
```
