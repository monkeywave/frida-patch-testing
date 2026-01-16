# Creating Patches

Guide to creating patches for Frida components.

## Overview

Patches let you modify Frida source code without maintaining a full fork.
They're ideal for:
- Small fixes
- Experimental features
- Testing before submitting upstream

## Patch Format

Patches should be in git format-patch format:

```
From: Your Name <email@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
Subject: [PATCH] component: brief description

Detailed explanation of the change.

---
 path/to/file.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/path/to/file.c b/path/to/file.c
...
```

## Creating Patches

### Method 1: git format-patch (Recommended)

1. Clone the component:
   ```bash
   git clone https://github.com/frida/frida-gum.git
   cd frida-gum
   ```

2. Create a feature branch:
   ```bash
   git checkout -b my-fix
   ```

3. Make your changes:
   ```bash
   # Edit files...
   vim gum/guminterceptor.c
   ```

4. Commit with a descriptive message:
   ```bash
   git add -A
   git commit -m "interceptor: add safety check for null pointers"
   ```

5. Generate the patch:
   ```bash
   git format-patch -1 HEAD
   # Creates: 0001-interceptor-add-safety-check-for-null-pointers.patch
   ```

6. Move to patches directory:
   ```bash
   mv 0001-*.patch /path/to/patches/frida-gum/
   ```

### Method 2: Multiple Commits

For a series of related changes:

```bash
# Make multiple commits
git commit -m "interceptor: refactor lock handling"
git commit -m "interceptor: add atfork handlers"
git commit -m "interceptor: improve error messages"

# Generate patches for all commits
git format-patch -3 HEAD
# Creates:
# 0001-interceptor-refactor-lock-handling.patch
# 0002-interceptor-add-atfork-handlers.patch
# 0003-interceptor-improve-error-messages.patch
```

### Method 3: From Upstream PR

If someone has submitted a PR you want to test:

```bash
# Add their fork as remote
git remote add contributor https://github.com/contributor/frida-gum.git

# Fetch their branch
git fetch contributor feature-branch

# Generate patches
git format-patch origin/main..contributor/feature-branch
```

## Patch Naming

Patches are applied in alphabetical order. Use numbered prefixes:

```
0001-first-change.patch      # Applied first
0002-second-change.patch     # Applied second
0010-later-change.patch      # Applied third (sorts after 0002)
```

## Testing Patches

Before building, verify patches apply cleanly:

```bash
cd frida-gum  # or component directory

# Test without applying
git apply --check /path/to/patch.patch

# Apply patch
git apply /path/to/patch.patch

# If context doesn't match exactly, try:
git apply -C1 /path/to/patch.patch
```

## Updating Patches

When Frida updates, patches may need adjustment:

1. Clone current Frida component
2. Apply your changes manually
3. Generate new patch
4. Replace old patch file

## Tips

### Keep Patches Small

Each patch should make one logical change. This makes them:
- Easier to review
- Easier to update when Frida changes
- Easier to upstream

### Write Good Commit Messages

Follow Frida's style:
```
component: brief description

Longer explanation of why this change is needed
and how it works.
```

### Test Thoroughly

Before distributing patches:
1. Build with the patch
2. Run existing tests
3. Test your specific use case
