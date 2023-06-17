import logging
import os

import tldextract

logging.basicConfig(filename='domain_verification.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def is_valid_domain(domain):
    ext = tldextract.extract(domain)
    return ext.suffix != ''

def should_remove_domain(domain):
    return domain.startswith("ci4.googleusercontent.com") or domain.startswith("ci3.googleusercontent.com") or domain.startswith("i.imgur.com")

def filter_invalid_domains(file_path):
    valid_domains = []
    removed_domains = []
    with open(file_path, 'r+') as file:
        lines = file.readlines()
        lines = sorted(set(lines))  # Sort and remove duplicates
        file.seek(0)  # Move the file pointer to the beginning
        file.truncate()  # Clear the file content
        for line in lines:
            domain = line.strip()
            if is_valid_domain(domain) and not should_remove_domain(domain):
                file.write(line)
                valid_domains.append(domain)
            else:
                removed_domains.append(domain)
                logging.info(f"Removed invalid domain: {domain}")
    return valid_domains, removed_domains

def process_text_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                valid_domains, removed_domains = filter_invalid_domains(file_path)
                print(f"Processed file: {file_path}")
                print("Valid Domains:")
                print(valid_domains)
                print("Removed Domains:")
                print(removed_domains)

# Usage example
current_directory = os.getcwd()
process_text_files(current_directory)
