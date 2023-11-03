#!/usr/bin/env python3
"""
This script creates directories and populates them with Sigma rules based on
different configurations for release archive packages. The directories will be
created according to the configuration level and platform of the rules.

Usage:
    To run this script, first navigate to the `pySigma-backend-uberAgent`
    directory and create a `build` directory. Then execute the script
    with the path to the Sigma rules as an argument:

    ```
    cd pySigma-backend-uberAgent
    mkdir build
    cd build
    ../copy-rules.py "/path/to/sigma/rules"
    ```

Arguments:
    rule_path: Path to the directory containing Sigma rule files.
"""


import os
import shutil
import sys
import argparse
import yaml

LEVEL = ["informational", "low", "medium", "high", "critical"]
PLATFORM = ["windows", "macos", "common"]


def select_rules(rules_path) -> dict:
    result = {}

    def yield_next_rule_file_path(rule_path: str) -> str:
        for root, _, files in os.walk(rule_path):
            for file in files:
                if file.endswith(".yml"):
                    yield os.path.join(root, file)

    def get_rule_yaml(file_path: str) -> dict:
        data = []
        with open(file_path, encoding="utf-8") as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)
        return data

    for file in yield_next_rule_file_path(rule_path=rules_path):
        rule_yaml = get_rule_yaml(file_path=file)
        if len(rule_yaml) != 1:
            print("[E] rule {} is a multi-document file and will be skipped".format(file))
            continue

        rule = rule_yaml[0]
        logsource = rule["logsource"]

        # Base filter: Include rule if level is present.
        include = "level" in rule

        # Include if product is not specified (common)
        platform = "common"

        if "product" in logsource:
            # Ensure to read the platform from rule.
            platform = logsource["product"]

        # Make sure the platform matches.
        include = include and platform in PLATFORM

        if include:
            key = "sigma-{}-{}".format(rule["level"], platform)
            if key not in result:
                result[key] = []
            else:
                result[key].append(file)

    return result


def write_directory(outdir: str, selected_rules: list):
    # Check if the directory already exists
    if os.path.exists(outdir):
        raise FileExistsError(f"Directory '{outdir}' already exists.")

    # Create the directory
    os.makedirs(outdir)

    # Copy the selected files into the directory
    for rule_path in selected_rules:
        # Get the file name from the rule_path
        file_name = os.path.basename(rule_path)

        # Construct the destination path
        dest_path = os.path.join(outdir, file_name)

        # Copy the file
        shutil.copy(rule_path, dest_path)


def main(args) -> int:

    print("[I] Parsing and selecting rules, this will take some time...")
    selected_rules = select_rules(args.rule_path)
    for k in selected_rules.keys():
        rules = selected_rules[k]
        write_directory(k, rules)
        print("[I] Selected {} rules [{}]".format(len(rules), k))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Creates directories with selected Sigma rules.")
    parser.add_argument("rule_path", help="Path to the directory containing Sigma rule files.")
    args = parser.parse_args()

    sys.exit(main(args))
