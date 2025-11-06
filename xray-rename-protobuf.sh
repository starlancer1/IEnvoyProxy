#!/bin/bash
###
# Path: xray-rename-protobuf.sh
# Renames all Xray protobuf files to avoid conflicts with V2Ray
# This script adds xray_ prefix to .proto files and regenerates .pb.go files
# Usage: Called by build.sh after patching
###

# exit on error
set -e

echo "Renaming Xray protobuf files to avoid conflicts with V2Ray..."

# Navigate to Xray-core directory
pushd "$TMPDIR/Xray-core"

# Find all .proto files and rename them by adding xray_ prefix
find . -name "*.proto" -type f | while read proto_file; do
    dir=$(dirname "$proto_file")
    base=$(basename "$proto_file")
    
    # Skip if already has xray_ prefix
    if [[ "$base" == xray_* ]]; then
        continue
    fi
    
    new_name="xray_${base}"
    new_path="${dir}/${new_name}"
    
    echo "Renaming: $proto_file -> $new_path"
    mv "$proto_file" "$new_path"
    
    # Update all imports in .proto files that reference this file
    old_import=$(echo "$proto_file" | sed 's|^\./||')
    new_import=$(echo "$new_path" | sed 's|^\./||')
    
    # Cross-platform sed: use -i.bak then remove backup files (works on both Linux and macOS)
    find . -name "*.proto" -type f -exec sed -i.bak "s|import \"${old_import}\"|import \"${new_import}\"|g" {} \; -exec rm {}.bak \;
done

echo "Done renaming proto files"
echo "Now regenerating all .pb.go files..."

# Regenerate all protobuf files
find . -name "xray_*.proto" -type f | while read proto_file; do
    echo "Generating: $proto_file"
    protoc --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. "$proto_file" 2>/dev/null || protoc --go_out=paths=source_relative:. "$proto_file"
done

echo "Renaming .pb.go files back to original names..."

# Rename all xray_*.pb.go files back to *.pb.go to maintain Go package structure
find . -name "xray_*.pb.go" -type f | while read file; do
    dir=$(dirname "$file")
    base=$(basename "$file" | sed 's/^xray_//')
    new_path="${dir}/${base}"
    echo "Renaming: $file -> $new_path"
    mv "$file" "$new_path"
done

popd

echo "Xray protobuf renaming complete!"

