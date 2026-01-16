# Troubleshooting

Common issues and solutions.

## Build Issues

### Docker Build Fails

**Symptom**: `docker build` command fails

**Solutions**:
1. Ensure Docker is running:
   ```bash
   docker info
   ```

2. Check available disk space:
   ```bash
   df -h
   ```

3. Clear Docker cache and retry:
   ```bash
   docker system prune
   ./build/run.sh
   ```

### Out of Memory

**Symptom**: Build killed, OOM errors

**Solutions**:
1. Increase Docker memory limit (Docker Desktop settings)
2. Close other applications
3. Build fewer targets at once

### Network Errors

**Symptom**: Git clone fails, npm install fails

**Solutions**:
1. Check internet connection
2. Retry (transient failures are common)
3. Use a VPN if repositories are blocked

## Patch Issues

### Patch Doesn't Apply

**Symptom**: `git apply` fails with conflicts

**Causes**:
- Frida source has changed since patch was created
- Wrong component directory
- Corrupted patch file

**Solutions**:

1. Check patch is in correct directory:
   ```bash
   ls patches/frida-gum/*.patch  # for frida-gum patches
   ```

2. Test patch manually:
   ```bash
   git apply --check your-patch.patch
   ```

3. Try with reduced context:
   ```bash
   git apply -C1 your-patch.patch
   ```

4. Regenerate patch against current Frida version

### Wrong Patch Order

**Symptom**: Later patches fail because earlier ones weren't applied

**Solution**: Rename patches with proper numeric prefixes:
```
0001-first.patch
0002-second.patch
```

### Line Ending Issues

**Symptom**: Patch shows as completely different

**Solution**: Convert to Unix line endings:
```bash
dos2unix your-patch.patch
```

## Custom Repository Issues

### Clone Fails

**Symptom**: Can't clone custom repository

**Causes**:
- Wrong URL
- Private repository without authentication
- Branch doesn't exist

**Solutions**:

1. Verify URL works:
   ```bash
   git ls-remote https://github.com/user/repo
   ```

2. For private repos, use SSH:
   ```yaml
   repository: "git@github.com:user/repo.git"
   ```

3. Check branch exists:
   ```bash
   git ls-remote --heads https://github.com/user/repo branch-name
   ```

### Incompatible Versions

**Symptom**: Build fails with API errors

**Cause**: Custom repository is out of sync with Frida version

**Solution**: Update fork to match target Frida version

## Output Issues

### No Output Files

**Symptom**: Build completes but `output/` is empty

**Solutions**:

1. Check build actually succeeded (look for errors in log)
2. Verify Docker volume mount:
   ```bash
   docker run -v $(pwd)/output:/output ...
   ```

3. Check permissions on output directory

### Wrong Architecture

**Symptom**: Binary doesn't run on target device

**Solution**: Specify correct architecture in config:
```yaml
build:
  architecture: "arm64"  # or "x86_64"
```

## Getting Help

1. Check the Frida documentation: https://frida.re/docs/
2. Search Frida GitHub issues
3. Open an issue in this repository with:
   - Your config.yaml
   - Error messages
   - Steps to reproduce
