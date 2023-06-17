""" THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. """

# pylint: disable=C0103, C0116, W0621
# Author : James Sawyer
# Copyright : Copyright (c) 2023 James Sawyer

import json
import logging
import os
import re

import requests
import tldextract

logging.basicConfig(filename='domain_verification.log', level=logging.INFO, format='%(asctime)s - %(message)s')

whitelist_domains = [
    "accounts.google.com",
    "docs.google.com",
    "drive.google.com",
    "play.google.com",
    "script.google.com",
    "sites.google.com",
    "storage.cloud.google.com"
    "www.google.com",
    "www.googleapis.com",
    "www.gstatic.com",
    "www.youtube.com",
    "youtube.com",
    "ytimg.com",
    "ytimg.l.google.com",
    "ytimg.l.googleusercontent.com",
    "ytimg.googleusercontent.com",
    "ci3.googleusercontent.com",
    "ci4.googleusercontent.com",
    "i.imgur.com"]

def is_ipv4(ip):
    match = re.match(r"^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
    if not match:
        return False
    quad = []
    for number in match.groups():
        quad.append(int(number))
    if quad[0] < 1:
        return False
    for number in quad:
        if number > 255 or number < 0:
            return False
    return True

def is_valid_domain(domain):
    ext = tldextract.extract(domain)
    return ext.suffix != ''

def should_remove_domain(domain):
    # any in whitelist domains
    return domain in whitelist_domains

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

# Phishtank URL
url = "http://data.phishtank.com/data/online-valid.json"

# Fetch Phishtank data
response = requests.get(url, headers={'User-Agent': "phishtank/JamesSawyer12"})
print(response.status_code)

# Extract phishing domains
phish_domains = []
pretty_json = json.loads(response.text)
for p in pretty_json:
    if str(p["online"]) == "yes":
        parsed_uri = urlparse(p["url"])
        if is_ipv4(str(parsed_uri.netloc)) == False:  # in this case if it's NOT an IP!
            if str(parsed_uri.netloc) not in whitelist_domains:
                phish_domains.append(parsed_uri.netloc)

phish_domains = sorted(list(set(phish_domains)))

# Save phishing domains to a file
with open('phish_domains.txt', 'w') as f:
    for domain in phish_domains:
        f.write(f"{domain}\n")

# Process text files in the current directory
current_directory = os.getcwd()
process_text_files(current_directory)
