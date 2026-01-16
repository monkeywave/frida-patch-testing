#!/usr/bin/env python3
"""
Frida Patch Testing Framework - Configuration Parser

Parses config.yaml and outputs shell variables for use in build.sh
"""

import sys
import yaml

def main():
    if len(sys.argv) < 2:
        print("Usage: parse-config.py <config.yaml>", file=sys.stderr)
        sys.exit(1)

    config_path = sys.argv[1]

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading config: {e}", file=sys.stderr)
        sys.exit(1)

    # Output shell variables
    frida = config.get('frida', {})
    print(f'FRIDA_VERSION="{frida.get("version", "latest")}"')
    print(f'FRIDA_REPO="{frida.get("repository", "https://github.com/frida/frida.git")}"')

    # Components
    components = config.get('components', {})
    for name in ['frida-gum', 'frida-core', 'frida-python', 'frida-tools']:
        comp = components.get(name, {})
        var_name = name.replace('-', '_').upper()

        print(f'{var_name}_SOURCE="{comp.get("source", "official")}"')
        print(f'{var_name}_PATCHES="{str(comp.get("patches", True)).lower()}"')
        print(f'{var_name}_REPO="{comp.get("repository", "")}"')
        print(f'{var_name}_BRANCH="{comp.get("branch", "")}"')

    # Build config
    build = config.get('build', {})
    targets = build.get('targets', ['frida-server'])
    print(f'BUILD_TARGETS="{" ".join(targets)}"')
    print(f'BUILD_ARCH="{build.get("architecture", "auto")}"')
    print(f'BUILD_DEBUG="{str(build.get("debug", False)).lower()}"')

    # Output config
    output = config.get('output', {})
    print(f'OUTPUT_DIR="{output.get("directory", "./output")}"')

if __name__ == '__main__':
    main()
