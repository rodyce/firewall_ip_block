# Download list of IP ranges by country with cURL:
# curl -o {LOCAL_FILE_NAME} "https://www.ip2location.com/download?token={DOWNLOAD_TOKEN}&file={DATABASE_CODE}"


import argparse
import os
import time
import re

import googleapiclient.discovery

DEFAULT_PRIORITY = 500
reg = r"((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(/(3[012]|[12]\d|\d))$"
cidr_pattern = re.compile(reg)


def firewall_exists(project, fw_api, fw_name):
    result = fw_api.list(project=project).execute()
    if not "items" in result:
        return False
    fw_names = (item["name"] for item in result["items"])
    return fw_name in fw_names


def is_valid_cidr(cidr):
    return bool(cidr_pattern.match(cidr))


def load_cidr_source_ranges(filename):
    with open(filename) as f:
        return [cidr.rstrip() for cidr in f.readlines() if is_valid_cidr(cidr)]


def create_firewall_definition(fw_name, source_ranges):
    if not isinstance(source_ranges, list) or not source_ranges:
        raise Exception("Source ranges must be a non-empty list")
    return {
        "name": fw_name,
        "direction": "INGRESS",
        "priority": DEFAULT_PRIORITY,
        "description": fw_name,
        "denied": [
            {
                "IPProtocol": "all"
            }
        ],
        "sourceRanges": source_ranges
    }


def create_firewall_update(fw_name, new_source_ranges):
    if not isinstance(new_source_ranges, list) or not new_source_ranges:
        raise Exception("Source ranges must be a non-empty list")
    return {
        "name": fw_name,
        "sourceRanges": new_source_ranges
    }


def main(project, cidr_file, firewall_name):
    compute = googleapiclient.discovery.build("compute", "v1")
    firewall_api = compute.firewalls()

    if not firewall_exists(project, firewall_api, firewall_name):
        source_ranges = load_cidr_source_ranges(cidr_file)
        fw_definition = create_firewall_definition(
            firewall_name, source_ranges)
        firewall_api.insert(project=project, body=fw_definition).execute()
        print("Firewall {} successfuly created with {} source range(s)".format(repr(firewall_name), ))
    else:
        print("Update FW definition")
        new_source_ranges = load_cidr_source_ranges(cidr_file)
        fw_update_data = create_firewall_update(
            firewall_name, new_source_ranges)
        firewall_api.update(
            project=project, firewall=firewall_name, body=fw_update_data).execute()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("project_id", help="Your Google Cloud project ID.")
    parser.add_argument(
        "cidr_file", help="File with IP ranges to exclude (CIDR format)")
    parser.add_argument(
        "firewall_name", help="Name of the firewall rule to sync with file")

    args = parser.parse_args()

    main(args.project_id, args.cidr_file, args.firewall_name)
# [END run]
