import os
import base64
import re
import zipfile
import tempfile
import shutil

def is_base64(encoded_string):
    """
    Check if a string is valid base64 encoded.
    
    Args:
        encoded_string: The string to check
        
    Returns:
        bool: True if the string is valid base64, False otherwise
    """
    try:
        # Add padding if needed (base64 strings must be multiples of 4)
        missing_padding = len(encoded_string) % 4
        if missing_padding:
            encoded_string += '=' * (4 - missing_padding)
        
        # Try to decode and re-encode to verify it's valid base64
        decoded = base64.b64decode(encoded_string, validate=False)
        re_encoded = base64.b64encode(decoded).decode().rstrip('=')
        return re_encoded == encoded_string.rstrip('=')
    except Exception:
        return False

def decode_base64(encoded_string):
    """
    Decode a base64 string with proper padding.
    
    Args:
        encoded_string: The base64 string to decode
        
    Returns:
        str: The decoded string
    """
    # Add padding if needed
    if len(encoded_string) % 4:
        encoded_string += '=' * (4 - len(encoded_string) % 4)
    return base64.b64decode(encoded_string).decode(errors='ignore')

def find_secret_base64(file_path):
    """
    Search a file for double-encoded base64 strings containing secrets.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        list: List of tuples containing (original, decoded_secret)
    """
    secret_matches = []
    
    with open(file_path, 'r', errors='ignore') as file:
        for line in file:
            # Find potential base64 strings (20+ characters of base64 alphabet)
            potential_base64 = re.findall(r'[A-Za-z0-9+/=]{20,}', line)
            
            for encoded in potential_base64:
                if is_base64(encoded):
                    # First decode
                    intermediate = decode_base64(encoded)
                    
                    # Check if first decode is also base64
                    if is_base64(intermediate):
                        # Second decode to get the secret
                        decoded_secret = decode_base64(intermediate)
                        
                        # Check if it contains a secret
                        if '"isSecret":true' in decoded_secret:
                            secret_matches.append((encoded, decoded_secret))
    
    return secret_matches

def extract_zip(zip_path, extract_path):
    """
    Extract a zip file to a temporary directory.
    
    Args:
        zip_path: Path to the zip file
        extract_path: Path where to extract the zip file
        
    Returns:
        bool: True if extraction was successful, False otherwise
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        return True
    except Exception as e:
        print(f"Error extracting {zip_path}: {e}")
        return False

def scan_for_secrets(directory):
    """
    Recursively scan a directory for files containing secret base64 strings.
    Handles both regular files and zip files.
    
    Args:
        directory: Directory path to scan
        
    Returns:
        tuple: (results dictionary, total files scanned, files with secrets)
    """
    results = {}
    total_files = 0
    files_with_secrets = 0
    
    # Create a temporary directory for zip extraction
    with tempfile.TemporaryDirectory() as temp_dir:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                total_files += 1
                
                # Handle zip files
                if file.lower().endswith('.zip'):
                    print(f"\nProcessing zip file: {file}")
                    zip_extract_path = os.path.join(temp_dir, os.path.splitext(file)[0])
                    os.makedirs(zip_extract_path, exist_ok=True)
                    
                    if extract_zip(file_path, zip_extract_path):
                        # Scan the extracted contents
                        for extracted_root, _, extracted_files in os.walk(zip_extract_path):
                            for extracted_file in extracted_files:
                                extracted_path = os.path.join(extracted_root, extracted_file)
                                total_files += 1
                                matches = find_secret_base64(extracted_path)
                                if matches:
                                    files_with_secrets += 1
                                    # Store results with original zip file path
                                    results[f"{file_path}/{os.path.relpath(extracted_path, zip_extract_path)}"] = matches
                else:
                    # Handle regular files
                    matches = find_secret_base64(file_path)
                    if matches:
                        files_with_secrets += 1
                        results[file_path] = matches
    
    return results, total_files, files_with_secrets

def print_results(results, total_files, files_with_secrets):
    """
    Print the results in a readable format.
    
    Args:
        results: Dictionary of results from scan_for_secrets
        total_files: Total number of files scanned
        files_with_secrets: Number of files containing secrets
    """
    print("\nScan Summary:")
    print("-" * 50)
    print(f"Total files scanned: {total_files}")
    print(f"Files containing secrets: {files_with_secrets}")
    print("-" * 50)
    
    if not results:
        print("\nNo secret base64 strings found in any of the scanned files.")
        return
    
    print("\nFound secret base64 strings in the following files:")
    print("-" * 50)
    
    for file_path, matches in results.items():
        print(f"\nFile: {file_path}")
        print("-" * 30)
        
        for i, (encoded, decoded_secret) in enumerate(matches, 1):
            print(f"\nMatch #{i}:")
            print(f"Original: {encoded}")
            print(f"Decoded Secret: {decoded_secret}")
            

def main():
    print("CVE-2025-30066 - GitHub Actions Supply Chain Vulnerability")
    print("Scan workflow logs for secrets potentially exposed via compromised tj-actions/changed-files")
    print("=" * 20)
    
    directory = input("\nEnter directory to scan: ").strip()
    
    if not os.path.exists(directory):
        print(f"Error: Directory '{directory}' does not exist.")
        return
    
    print("\nScanning...")
    results, total_files, files_with_secrets = scan_for_secrets(directory)
    print_results(results, total_files, files_with_secrets)

if __name__ == "__main__":
    main()
