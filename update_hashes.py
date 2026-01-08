#!/usr/bin/env python3
"""
Простой скрипт для обновления SHA256 хэшей, что тут сказать..
"""
import hashlib
import os
import sys
from pathlib import Path

def update_module_hashes():

    modules_dir = Path("modules")
    if not modules_dir.exists():
        print("❌ Modules directory not found")
        return False

    print("🔄 Updating SHA256 checksums...")

    sh_files = []
    for file in modules_dir.glob("*.sh"):
        if not file.name.startswith('.'):
            sh_files.append(file)

    if not sh_files:
        print("❌ No .sh files found in modules directory")
        return False

    hashes = []

    for sh_file in sorted(sh_files):
        sha256_hash = hashlib.sha256()
        with open(sh_file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        hashes.append(f"{file_hash}  {sh_file.name}")

        hash_file = sh_file.with_suffix('.sh.sha256')
        with open(hash_file, 'w') as f:
            f.write(file_hash)

        print(f"✓ {sh_file.name}: {file_hash[:16]}...")

    main_hash_file = modules_dir / "SHA256SUMS"
    with open(main_hash_file, 'w') as f:
        f.write("# SHA256 checksums for EN-OS modules\n")
        f.write("# Generated automatically - DO NOT EDIT MANUALLY\n\n")
        f.write('\n'.join(hashes))

    print(f"\n✅ Updated {len(sh_files)} modules")
    print(f"📄 Main hash file: {main_hash_file}")

    return True

def verify_all_hashes():

    print("🔍 Verifying all checksums...")

    modules_dir = Path("modules")
    main_hash_file = modules_dir / "SHA256SUMS"

    if not main_hash_file.exists():
        print("❌ Main hash file not found")
        return False

    with open(main_hash_file, 'r') as f:
        lines = f.readlines()

    verified = 0
    failed = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parts = line.split('  ')
        if len(parts) >= 2:
            expected_hash = parts[0].strip()
            filename = parts[1].strip()
            filepath = modules_dir / filename

            if filepath.exists():
                sha256_hash = hashlib.sha256()
                with open(filepath, 'rb') as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                actual_hash = sha256_hash.hexdigest()

                if actual_hash == expected_hash:
                    print(f"✅ {filename}: OK")
                    verified += 1
                else:
                    print(f"❌ {filename}: HASH MISMATCH")
                    print(f"   Expected: {expected_hash}")
                    print(f"   Actual:   {actual_hash}")
                    failed += 1
            else:
                print(f"⚠ {filename}: FILE NOT FOUND")
                failed += 1

    print(f"\n📊 Results: ✅ {verified} verified, ❌ {failed} failed")

    return failed == 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--verify":
            verify_all_hashes()
        elif sys.argv[1] == "--update":
            update_module_hashes()
        else:
            print("Usage:")
            print("  python update_hashes.py --update    # Update all hashes")
            print("  python update_hashes.py --verify    # Verify all hashes")
    else:
        update_module_hashes()
