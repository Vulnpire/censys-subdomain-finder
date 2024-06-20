#!/usr/bin/env python3

import sys
import os
import time
from censys.search import CensysCerts
from censys.common.exceptions import (
    CensysUnauthorizedException,
    CensysRateLimitExceededException,
    CensysException,
)
from dotenv import load_dotenv
import argparse

load_dotenv()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
MAX_PER_PAGE = 100
COMMUNITY_PAGES = 10

def read_file(filename):
    """Read lines from a file and return them as a list."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Finds subdomains of a domain using Censys API
def find_subdomains(domain, api_id, api_secret, limit_results):
    subdomains = set()
    try:
        censys_certificates = CensysCerts(
            api_id=api_id, api_secret=api_secret, user_agent=USER_AGENT
        )
        certificate_query = "names: %s" % domain
        pages = -1  # unlimited
        if limit_results:
            pages = COMMUNITY_PAGES
        certificates_search_results = censys_certificates.search(
            certificate_query,
            per_page=MAX_PER_PAGE,
            pages=pages
        )

        for page in certificates_search_results:
            for search_result in page:
                subdomains.update(search_result["names"])

    except CensysUnauthorizedException:
        sys.stderr.write("[-] Your Censys credentials look invalid.\n")
        exit(1)
    except CensysRateLimitExceededException:
        sys.stderr.write(
            "[-] Looks like you exceeded your Censys account limits rate. Exiting\n"
        )
    except CensysException as e:
        sys.stderr.write("[-] Something bad happened, " + repr(e) + "\n")

    return subdomains

# Filters out uninteresting subdomains
def filter_subdomains(domain, subdomains):
    return [
        subdomain
        for subdomain in subdomains
        if "*" not in subdomain and subdomain.endswith(domain) and subdomain != domain
    ]

# Prints the list of found subdomains to stdout (clear output: only subdomains)
def print_subdomains(subdomains):
    for subdomain in subdomains:
        print(subdomain)

# Saves the list of found subdomains to an output file
def save_subdomains_to_file(subdomains, output_file):
    if output_file is None or len(subdomains) == 0:
        return

    try:
        with open(output_file, "w") as f:
            for subdomain in subdomains:
                f.write(subdomain + "\n")
    except IOError as e:
        sys.stderr.write(
            "[-] Unable to write to output file %s : %s\n" % (output_file, e)
        )

def process_domain(domain, output_file, censys_api_id, censys_api_secret, limit_results):
    subdomains = find_subdomains(
        domain, censys_api_id, censys_api_secret, limit_results
    )
    subdomains = filter_subdomains(domain, subdomains)
    print_subdomains(subdomains)
    save_subdomains_to_file(subdomains, output_file)

def main(domains, output_file, censys_api_id, censys_api_secret, limit_results):
    for domain in domains:
        process_domain(domain, output_file, censys_api_id, censys_api_secret, limit_results)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Find subdomains using the Censys API.")
    parser.add_argument(
        "-d", "--domain", type=str, help="The domain to search for subdomains."
    )
    parser.add_argument(
        "-i", "--input-file", type=str, help="File with list of domains to search for subdomains."
    )
    parser.add_argument(
        "-o", "--output-file", type=str, help="File to save the list of found subdomains."
    )
    parser.add_argument(
        "-c", "--censys-api-id", type=str, help="Censys API ID."
    )
    parser.add_argument(
        "-s", "--censys-api-secret", type=str, help="Censys API Secret."
    )
    parser.add_argument(
        "--commercial", action="store_true", help="Use commercial account limits (unlimited results)."
    )

    args = parser.parse_args()

    censys_api_id = args.censys_api_id or os.getenv("CENSYS_API_ID")
    censys_api_secret = args.censys_api_secret or os.getenv("CENSYS_API_SECRET")

    if not censys_api_id or not censys_api_secret:
        sys.stderr.write(
            "[!] Please set your Censys API ID and secret using environment variables or command-line arguments.\n"
        )
        exit(1)

    limit_results = not args.commercial
    if limit_results:
        sys.stderr.write(
            f"[*] Applying free plan limits ({MAX_PER_PAGE * COMMUNITY_PAGES} results at most)\n"
        )

    if args.input_file:
        domains = read_file(args.input_file)
    elif args.domain:
        domains = [args.domain]
    else:
        sys.stderr.write("[!] You must provide a domain or an input file with domains.\n")
        exit(1)

    main(domains, args.output_file, censys_api_id, censys_api_secret, limit_results)

