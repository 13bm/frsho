# Frsho

This script allows you to fetch and parse host information from [Shodan](https://www.shodan.io/) for one or multiple hosts (IP addresses or domains). It outputs the data in JSON format, suitable for further processing with tools like `jq`. The script can be used as a standalone command-line tool or imported as a library in other Python scripts.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Usage](#command-line-usage)
    - [Single Host](#single-host)
    - [Multiple Hosts](#multiple-hosts)
    - [Saving Outputs](#saving-outputs)
  - [Using as a Library](#using-as-a-library)
- [Tips and Tricks](#tips-and-tricks)
  - [Using `jq` for JSON Processing](#using-jq-for-json-processing)
  - [Converting Base64 Images to Image Files](#converting-base64-images-to-image-files)
- [Notes](#notes)

## Features

- Fetches host information from Shodan, including:
  - IP address
  - Tags
  - General information (hostnames, domains, country, city, organization, ISP, ASN)
  - Vulnerabilities summary (categorized by severity)
  - Web technologies used
  - Open ports and their details, including associated CVEs
- Supports querying multiple hosts at once
- Outputs combined JSON data suitable for piping to `jq`
- Can save individual host data and a master output file when using the `--output` flag
- Can be imported and used as a library in other Python scripts

## Requirements

- Python 3.6 or higher
- Packages:
  - `requests`
  - `beautifulsoup4`

Install the required packages using:

```bash
pip install requests beautifulsoup4
```

## Installation

Clone this repository or download the `frsho.py` script directly.

```bash
git clone https://github.com/yourusername/frsho.git
cd frsho
```

## Usage

### Command-Line Usage

#### Single Host

To fetch information for a single host:

```bash
python frsho.py xxx.xxx.xxx.xxx
```

#### Multiple Hosts

To fetch information for multiple hosts:

```bash
python frsho.py xxx.xxx.xxx.xxx example.com xxx.xxx.xxx.xxx
```

#### Saving Outputs

To save individual outputs for each host and a master output file containing all hosts' data:

```bash
python frsho.py xxx.xxx.xxx.xxx example.com xxx.xxx.xxx.xxx --output
```

- Individual host data will be saved as `xxx.xxx.xxx.xxx.json`, `example.com.json`, etc.
- The master output containing all hosts' data will be saved as `all_hosts.json`.

### Using as a Library

You can import the `fetch_and_parse_shodan` function into your own Python scripts.

**Example:**

```python
from frsho import fetch_and_parse_shodan
import json

hosts = ['xxx.xxx.xxx.xxx', 'example.com', 'xxx.xxx.xxx.xxx']
all_hosts_data = []

for host in hosts:
    data = fetch_and_parse_shodan(host)
    all_hosts_data.append({
        "Host": host,
        "results": data
    })

# Use the data as needed
print(json.dumps(all_hosts_data, indent=4))
```

**Running the Script:**

```bash
python your_script.py
```

## Tips and Tricks

### Using `jq` for JSON Processing

Since the script outputs JSON data, you can use `jq` to process and filter the information.

**Installing `jq`:**

On Ubuntu/Debian:

```bash
sudo apt-get install jq
```

On macOS using Homebrew:

```bash
brew install jq
```

**Examples:**

1. **Pretty-print the JSON output:**

   ```bash
   python frsho.py xxx.xxx.xxx.xxx | jq '.'
   ```

2. **Extract all CVEs with a High severity:**

   ```bash
   python frsho.py xxx.xxx.xxx.xxx | jq '.[].results.vulnerabilities_summary.cves_by_severity.High'
   ```

3. **List all open ports for each host:**

   ```bash
   python frsho.py xxx.xxx.xxx.xxx example.com | jq '.[] | {Host: .Host, OpenPorts: [.results.open_ports[].port]}'
   ```

4. **Find hosts with more than 5 High severity CVEs:**

   ```bash
   python frsho.py xxx.xxx.xxx.xxx example.com | jq '.[] | select(.results.vulnerabilities_summary.severity_counts.High > 5) | .Host'
   ```

### Converting Base64 Images to Image Files

If the script or the data contains any base64-encoded images (e.g., screenshots), you can decode and save them as image files.

**Example:**

Suppose you have a base64 string representing an image:

```json
"image_base64": "/9j/4AAQSkZJRgABAQAAAQABAAD..."
```

**Steps to Decode and Save the Image:**

1. **Extract the Base64 String:**

   Use `jq` to extract the base64 string:

   ```bash
   base64_string=$(python frsho.py host | jq -r '.[].results.image_base64')
   ```

2. **Decode and Save the Image:**

   ```bash
   echo "$base64_string" | base64 --decode > image.jpg
   ```

3. **View the Image:**

   Open the image file with your preferred image viewer.

**Note:** The provided script does not currently extract or handle base64 images from Shodan. This example assumes that such data is present.

## Notes

- **Error Handling:** If an error occurs while fetching data for a host, the error message will be included in the `results` for that host.
- **Sanitization:** Filenames are sanitized to ensure they are valid and safe for use on different operating systems.
- **Master Output:** The master output `all_hosts.json` is only created when multiple hosts are provided and the `--output` flag is used.
- **Piping to `jq`:** The script outputs the combined JSON data to `stdout`, making it suitable for piping to `jq` or other JSON processing tools.

  **Example:**

  ```bash
  python frsho.py xxx.xxx.xxx.xxx example.com | jq '.'
  ```

**Disclaimer:** This script is intended for educational and lawful purposes only. Ensure that you have proper authorization to access and retrieve data from Shodan for the hosts you query. Unauthorized access or scraping of websites may violate their terms of service or applicable laws.
