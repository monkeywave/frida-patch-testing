# Patch Templates

These templates help you create properly formatted patches for Frida components.

## Template Files

### simple-function-hook.patch.template

Use this template when you need to:
- Add a hook or callback to an existing function
- Insert code at a specific location
- Make a small, localized change

### add-new-feature.patch.template

Use this template when you need to:
- Add new functions to a component
- Modify both headers and source files
- Implement a complete new feature

## Creating Your Own Patch

### Method 1: From Git (Recommended)

1. Clone the component you want to modify:
   ```bash
   git clone https://github.com/frida/frida-gum.git
   cd frida-gum
   ```

2. Create a branch for your changes:
   ```bash
   git checkout -b my-fix
   ```

3. Make your changes and commit:
   ```bash
   git add .
   git commit -m "component: description of change"
   ```

4. Generate the patch:
   ```bash
   git format-patch -1 HEAD
   # Creates: 0001-component-description-of-change.patch
   ```

5. Copy to the patches directory:
   ```bash
   cp 0001-*.patch /path/to/frida-patch-testing/patches/frida-gum/
   ```

### Method 2: Manual Diff

1. Create a copy of the original file
2. Make your changes
3. Generate diff:
   ```bash
   diff -u original.c modified.c > my-change.patch
   ```

4. Add patch header manually (see templates)

## Patch Naming Convention

Use numbered prefixes for ordering:
```
0001-first-change.patch      # Applied first
0002-second-change.patch     # Applied second
0010-later-change.patch      # Applied third
```

## Testing Your Patch

Before committing, verify your patch applies cleanly:

```bash
# Test without applying
git apply --check your-patch.patch

# Apply the patch
git apply your-patch.patch

# If it fails, try with more context
git apply -C1 your-patch.patch
```

## Common Issues

### Patch doesn't apply

- The source code has changed since the patch was created
- Line numbers have shifted
- Context lines don't match

**Solution**: Regenerate the patch against current Frida version

### Wrong line endings

Ensure patches use Unix line endings (LF, not CRLF):
```bash
dos2unix your-patch.patch
```
