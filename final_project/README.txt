=====================================================================
PHISHING URL DETECTOR
=====================================================================

Author: Jonathan Rios
Course: COMP-3721

PROJECT SUMMARY
This project is a static phishing URL detector that identifies malicious
links without opening a web browser or connecting to external servers.
Written entirely in standard Python 3 using only built-in libraries
(math, re, and urllib.parse), the tool parses a given URL and evaluates
it against 8 weighted rules—covering brand impersonation and
punycode, IP-address hosts, "@" redirects, excessive URL length,
suspicious subdomains, Shannon character entropy, unencrypted HTTP, and
sensitive keywords. Each URL receives a cumulative risk score and a
LOW, MEDIUM, or HIGH threat classification, and the script both
benchmarks its accuracy against a built-in dataset of 100 labeled URLs
and provides an interactive prompt to inspect individual links.

ARCHITECTURE DIAGRAM
Input URL
--- URL Parser (urllib.parse: extracts scheme, host, and lowercase URL)
--- 8-Rule Scorer (check_url)
    --- +3 pts: Brand impersonation / punycode, IP address host, @ symbol
    --- +2 pts: URL length >= 71, suspicious subdomains, entropy >= 4.5
    --- +1 pt : HTTP scheme, sensitive keywords
--- Risk Classifier (0-2: LOW | 3-5: MEDIUM [Flagged] | 6+: HIGH [Flagged])
    --- Mode 1: 100-URL Benchmark (prints accuracy, precision, recall, FPR, and errors)
    --- Mode 2: Interactive CLI Checker (prints score, risk level, flags, and warning)

FOLDER STRUCTURE
final_project
--- url_scorer.py : Main script containing the 8-rule scorer, 100-URL benchmark dataset, and interactive URL checker.
--- README.txt    : Project documentation, architecture, setup steps, and known limitations.

PREREQUISITES
- Operating System: Windows, macOS, or Linux
- Language: Python 3.11.4 (compatible with Python 3.6+)
- Tools & Dependencies: Terminal / Command Prompt; no third-party
  packages or external libraries are required.

SETUP AND INSTALL COMMANDS
1. Download or clone the project files into a local folder and
   navigate into that directory:
       cd path/to/final_project

2. Verify that Python 3 is installed:
       python --version

3. Install dependencies (none required—uses Python standard library):
       # No pip install needed

4. Run the benchmark and interactive URL checker:
       python url_scorer.py

KNOWN LIMITATIONS
- Only looks at the URL text: The program checks the link string itself
  and does not connect to the internet to check domain age, SSL
  certificates, or what is actually on the webpage.
- Shortened links and generic sites: Shortened URLs (like bit.ly or
  tinyurl.com) and phishing links that do not use big brand names or
  obvious keywords can slip past the rules (false negatives).
- Messy legitimate links: Real websites with really long links, random
  IDs/tokens in the URL, or lots of subdomains can sometimes hit 3+
  points and get flagged by mistake (false positives).
- Small brand list: The fake-brand rule only checks for 8 hardcoded
  companies (PayPal, Apple, Google, Microsoft, Amazon, Netflix,
  Facebook, and Chase).
- Fixed test data: The accuracy and recall numbers are tested on a
  hardcoded list of 100 URLs built into the script rather than a live
  feed or a separate train/test split.
- Can not tell the difference between shopping links and phishing links
  so will be seen as FN
=====================================================================