import requests
from bs4 import BeautifulSoup
import json
import argparse
import re
import ast
import os

def fetch_and_parse_shodan(host):
    url = f"https://www.shodan.io/host/{host}"
    headers = {
        "Host": "www.shodan.io",
        "Accept-Encoding": "json",
        "Accept": "*/*",
        "Accept-Language": "en-US;q=0.9,en;q=0.8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
        "Cache-Control": "max-age=0"
    }

    # Make the HTTP request
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code != 200:
        return {"error": f"Failed to fetch data for {host}, HTTP Status Code: {response.status_code}"}

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract IP and title
    ip_address_tag = soup.find("h2", id="host-title")
    ip_address = ip_address_tag.text.strip() if ip_address_tag and ip_address_tag.text else host

    # Extract tags
    tags_section = soup.find("div", id="tags")
    tags = [tag.text.strip() for tag in tags_section.find_all("a")] if tags_section else []

    # Extract General Information
    general_info_table = soup.find("table", class_="table u-full-width")
    general_info = {}
    if general_info_table:
        rows = general_info_table.find_all("tr")
        for row in rows:
            key_cell = row.find("td")
            value_cell = row.find("strong") or row.find("td", recursive=False)
            if key_cell and key_cell.text and value_cell and value_cell.text:
                key = key_cell.text.strip()
                value = value_cell.text.strip()
                general_info[key] = value

    # Extract Web Technologies
    web_technologies = {}
    webtech_section = soup.find("div", id="http-components")
    if webtech_section:
        categories = webtech_section.find_all("div", class_="category")
        for category in categories:
            category_heading = category.find("div", class_="category-heading")
            if not category_heading or not category_heading.text:
                continue
            category_name = category_heading.text.strip()
            techs = []
            tech_items = category.find_all("a", class_="text-dark")
            for tech_item in tech_items:
                tech_name_span = tech_item.find("span", class_="technology-name")
                if not tech_name_span or not tech_name_span.text:
                    continue
                tech_name = tech_name_span.text.strip()
                version_span = tech_item.find("span", class_="technology-version")
                version = version_span.text.strip() if version_span and version_span.text else ""
                techs.append({
                    "name": tech_name,
                    "version": version
                })
            web_technologies[category_name] = techs

    # Extract VULNS JavaScript variable
    vulns_script = soup.find("script", string=re.compile("const VULNS ="))
    vulns_data = {}
    if vulns_script and vulns_script.string:
        script_content = vulns_script.string
        # Extract the JSON-like data from the script
        match = re.search(r'const VULNS = ({.*});', script_content, re.DOTALL)
        if match:
            vulns_json_text = match.group(1)
            # Replace JavaScript boolean and null with Python equivalents
            vulns_json_text = vulns_json_text.replace('false', 'False').replace('true', 'True').replace('null', 'None')
            try:
                vulns_data = ast.literal_eval(vulns_json_text)
            except Exception as e:
                print(f"Error parsing VULNS data for {host}: {e}")

    # Create a mapping from CVE to its data
    cve_data_mapping = {}
    for cve_id, cve_info in vulns_data.items():
        cvss_score = cve_info.get('cvss', 0)
        summary = cve_info.get('summary', '')
        cve_data_mapping[cve_id] = {
            'cvss': cvss_score,
            'summary': summary,
            'ports': cve_info.get('ports', []),
            'verified': cve_info.get('verified', False)
        }

    # Initialize vulnerabilities summary
    vulnerabilities_summary = {
        'High': [],
        'Medium': [],
        'Low': [],
        'Unscored': []
    }

    # Extract open ports and their details
    ports_info = []
    all_cves = []
    ports_sections = soup.find_all("h6", class_="grid-heading")
    for port_section in ports_sections:
        try:
            # Extract port number
            port_id = port_section.get('id')
            if port_id:
                port_number = port_id
            else:
                strong_tag = port_section.find("strong")
                if strong_tag and strong_tag.text:
                    port_number = strong_tag.text.strip()
                else:
                    continue  # Skip if port number is not found

            # Extract protocol (assuming TCP as default)
            protocol = "tcp"

            # Extract timestamp and hash
            pre_tag = port_section.find("pre", class_="u-pull-right text-secondary")
            if pre_tag and pre_tag.text:
                pre_text = pre_tag.text.strip()
                hash_link = pre_tag.find("a")
                hash_value = hash_link.text.strip() if hash_link and hash_link.text else ""
                timestamp = pre_text.split("|")[-1].strip()
            else:
                hash_value = ""
                timestamp = ""

            # Extract banner/details
            banner_div = port_section.find_next_sibling("div", class_="card card-padding banner")
            if banner_div:
                # Extract product and version
                banner_title = banner_div.find("h1", class_="banner-title")
                if banner_title:
                    product_em = banner_title.find("em")
                    product = product_em.text.strip() if product_em and product_em.text else ""
                    version_span = banner_title.find("span")
                    version = version_span.text.strip() if version_span and version_span.text else ""
                else:
                    product = ""
                    version = ""

                # Extract preformatted content
                pre_content = banner_div.find("pre")
                banner_details = pre_content.text.strip() if pre_content and pre_content.text else ""

                # Extract CVEs if available
                cve_list = []
                cve_div = banner_div.find("div", class_="cve-list")
                if cve_div:
                    # Exclude <a> tags with class 'cve-tag-show-all'
                    cve_tags = cve_div.find_all("a", class_="cve-tag")
                    for cve_tag in cve_tags:
                        if 'cve-tag-show-all' not in cve_tag.get('class', []):
                            cve = cve_tag.text.strip()
                            cve_info = cve_data_mapping.get(cve, {})
                            cvss_score = cve_info.get('cvss', 0)
                            summary = cve_info.get('summary', '')
                            cve_entry = {
                                "cve": cve,
                                "cvss": cvss_score,
                                "summary": summary
                            }
                            cve_list.append(cve_entry)
                            all_cves.append(cve_entry)
                    # Sort CVEs by CVSS score in descending order
                    cve_list.sort(key=lambda x: x['cvss'], reverse=True)

                # Append port information
                ports_info.append({
                    "port": port_number,
                    "protocol": protocol,
                    "hash": hash_value,
                    "timestamp": timestamp,
                    "product": product,
                    "version": version,
                    "details": banner_details,
                    "cves": cve_list
                })
        except Exception as e:
            print(f"Error processing port section for {host}: {e}")
            continue

    # Categorize CVEs by severity
    severity_counts = {
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Unscored': 0
    }

    severity_levels = {
        'High': [],
        'Medium': [],
        'Low': [],
        'Unscored': []
    }

    for cve_entry in all_cves:
        cvss_score = cve_entry['cvss']
        if cvss_score >= 7.0:
            severity = 'High'
        elif 4.0 <= cvss_score < 7.0:
            severity = 'Medium'
        elif 0 < cvss_score < 4.0:
            severity = 'Low'
        else:
            severity = 'Unscored'
        severity_levels[severity].append(cve_entry)
        severity_counts[severity] += 1

    # Prepare vulnerabilities summary
    vulnerabilities_summary = {
        'total_cves': len(all_cves),
        'severity_counts': severity_counts,
        'cves_by_severity': severity_levels
    }

    # Create a JSON structure
    data = {
        "ip_address": ip_address,
        "tags": tags,
        "general_information": general_info,
        "vulnerabilities_summary": vulnerabilities_summary,
        "web_technologies": web_technologies,
        "open_ports": ports_info,
    }

    return data

def main():
    parser = argparse.ArgumentParser(description="Fetch and parse Shodan host information.")
    parser.add_argument("hosts", nargs='+', help="One or more hosts (IP addresses or domains) to query on Shodan.")
    parser.add_argument("--output", nargs='?', const='.', help="Specify output directory for JSON files.")
    args = parser.parse_args()

    output_dir = args.output  # None if not specified, or '.' (current directory) if --output is used without a path

    all_hosts_data = []

    # Process each host
    for host in args.hosts:
        # Fetch data
        shodan_data = fetch_and_parse_shodan(host)

        # Add to all_hosts_data
        all_hosts_data.append({
            "Host": host,
            "results": shodan_data
        })

        # Save individual host data to file if the --output option is specified
        if output_dir is not None:
            # Sanitize filename for safety
            filename = f"{re.sub(r'[^a-zA-Z0-9._-]', '_', host)}.json"
            # Ensure the output directory exists
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, filename)
            with open(file_path, 'w') as json_file:
                json.dump(shodan_data, json_file, indent=4)
            print(f"Output saved to {file_path}")

    # Print the combined JSON data to stdout
    print(json.dumps(all_hosts_data, indent=4))

    # Save master output file with all hosts data if --output is specified
    if output_dir is not None and len(args.hosts) > 1:
        master_file_path = os.path.join(output_dir, 'all_hosts.json')
        with open(master_file_path, 'w') as json_file:
            json.dump(all_hosts_data, json_file, indent=4)
        print(f"\nMaster output saved to {master_file_path}")

if __name__ == "__main__":
    main()
