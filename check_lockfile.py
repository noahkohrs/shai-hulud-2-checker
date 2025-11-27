import json
import os
import sys
import csv
import urllib.request
import io

# Configuration for sources
SOURCES = [
    {
        "url": "https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284",
        "type": "header_based",
        "name_col": "Package Name",
        "version_col": "Version"
    },
    {
        "url": "https://docs.google.com/spreadsheets/d/1PwtFi9Va9ihgrFQTsfPX7eifzmj68eva52mPWoaoxBE/export?format=csv&gid=689267983",
        "type": "index_based",
        "name_index": 1,
        "version_index": 2
    }
]

def download_csv(url):
    print(f"Downloading vulnerabilities from {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"Error downloading CSV from {url}: {e}")
        return None

def parse_header_based(csv_content, name_col, version_col):
    packages = []
    csv_file = io.StringIO(csv_content)
    reader = csv.DictReader(csv_file)
    for row in reader:
        # Normalize keys by stripping whitespace
        row_stripped = {k.strip(): v for k, v in row.items() if k}
        
        name = row_stripped.get(name_col)
        version = row_stripped.get(version_col)
        
        if name and version:
            packages.append({
                "name": name.strip(),
                "version": version.strip()
            })
    return packages

def parse_index_based(csv_content, name_index, version_index):
    packages = []
    csv_file = io.StringIO(csv_content)
    reader = csv.reader(csv_file)
    for row in reader:
        if len(row) > max(name_index, version_index):
            name = row[name_index]
            version = row[version_index]
            if name and version:
                packages.append({
                    "name": name.strip(),
                    "version": version.strip()
                })
    return packages

def update_vulnerabilities(output_json_path):
    all_packages = []
    seen = set()
    
    for source in SOURCES:
        content = download_csv(source["url"])
        if not content:
            continue
            
        print(f"Parsing data from {source['url']}...")
        extracted = []
        if source["type"] == "header_based":
            extracted = parse_header_based(content, source["name_col"], source["version_col"])
        elif source["type"] == "index_based":
            extracted = parse_index_based(content, source["name_index"], source["version_index"])
            
        print(f"Found {len(extracted)} entries.")
        
        for pkg in extracted:
            key = (pkg['name'], pkg['version'])
            if key not in seen:
                seen.add(key)
                all_packages.append(pkg)
                
    print(f"Total unique vulnerable packages: {len(all_packages)}")
    
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(all_packages, f, indent=4)
    print(f"Saved vulnerability list to {output_json_path}")
    
    return load_vulnerable_packages(output_json_path)

def load_vulnerable_packages(json_path):
    if not os.path.exists(json_path):
        print(f"Error: Vulnerable packages file not found at {json_path}")
        return {}
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    # Create a dictionary mapping package name to a set of vulnerable versions
    vulnerable_map = {}
    for item in data:
        name = item.get('name')
        version = item.get('version')
        
        if name and version:
            if name not in vulnerable_map:
                vulnerable_map[name] = set()
            vulnerable_map[name].add(version)
            
    return vulnerable_map

def get_package_name_from_path(path):
    # Handle root package
    if path == "":
        return None
        
    # Split by node_modules to handle nested paths
    # e.g. "node_modules/foo/node_modules/bar" -> ["", "foo/", "bar"]
    parts = path.split("node_modules/")
    
    # The last part is the package name
    if parts:
        return parts[-1]
    return None

def check_lockfile(lockfile_path, vulnerable_map):
    if not os.path.exists(lockfile_path):
        print(f"Error: Lockfile not found at {lockfile_path}")
        return

    with open(lockfile_path, 'r', encoding='utf-8') as f:
        lock_data = json.load(f)

    found_vulnerabilities = []

    # Check for 'packages' (npm v2/v3)
    if 'packages' in lock_data:
        print(f"Scanning 'packages' in {lockfile_path}...")
        for path, details in lock_data['packages'].items():
            package_name = get_package_name_from_path(path)
            if not package_name:
                continue
                
            version = details.get('version')
            
            if package_name in vulnerable_map:
                # Check if exact version match
                is_exact_match = version in vulnerable_map[package_name]
                found_vulnerabilities.append({
                    "name": package_name,
                    "version": version,
                    "path": path,
                    "match_type": "EXACT" if is_exact_match else "NAME_ONLY",
                    "vulnerable_versions": list(vulnerable_map[package_name])
                })
    
    # Fallback/Check for 'dependencies' (npm v1) if 'packages' is missing or empty
    elif 'dependencies' in lock_data:
        print(f"Scanning 'dependencies' in {lockfile_path} (v1 format)...")
        # Recursive function to check dependencies
        def check_deps(deps, current_path=""):
            for name, details in deps.items():
                version = details.get('version')
                path = f"{current_path}/node_modules/{name}" if current_path else f"node_modules/{name}"
                
                if name in vulnerable_map:
                    is_exact_match = version in vulnerable_map[name]
                    found_vulnerabilities.append({
                        "name": name,
                        "version": version,
                        "path": path,
                        "match_type": "EXACT" if is_exact_match else "NAME_ONLY",
                        "vulnerable_versions": list(vulnerable_map[name])
                    })
                
                if 'dependencies' in details:
                    check_deps(details['dependencies'], path)

        check_deps(lock_data['dependencies'])

    # Report results
    if found_vulnerabilities:
        print(f"\nFound {len(found_vulnerabilities)} suspicious packages:")
        print("-" * 100)
        print(f"{'Package':<30} | {'Version':<15} | {'Type':<15} | {'Location'}")
        print("-" * 100)
        for vuln in found_vulnerabilities:
            print(f"{vuln['name']:<30} | {vuln['version']:<15} | {vuln['match_type']:<15} | {vuln['path']}")
        print("-" * 100)
        
        # Save to file
        output_file = 'vulnerabilities_found.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(found_vulnerabilities, f, indent=4)
        print(f"\nDetailed report saved to {output_file}")
    else:
        print("\nNo suspicious packages found in the lockfile.")

if __name__ == "__main__":
    vulnerable_json = 'vulnerable_packages.json'
    
    if len(sys.argv) > 1:
        lockfile = sys.argv[1]
    else:
        print("Usage: python check_lockfile.py <path_to_package_lock.json>")
        print("No lockfile specified, defaulting to 'package-lock.json'...")
        lockfile = 'package-lock.json'
    
    # Download and update the vulnerabilities list first
    v_map = update_vulnerabilities(vulnerable_json)
    
    if not v_map:
        print("Failed to load vulnerabilities. Exiting.")
        sys.exit(1)

    print(f"Loaded {len(v_map)} unique vulnerable packages.")
    
    print(f"Checking {lockfile}...")
    check_lockfile(lockfile, v_map)
