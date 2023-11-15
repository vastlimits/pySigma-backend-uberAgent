#!/bin/bash

# -----------------------------------------------------------------------------
# Script: Sigma Rule Converter
# -----------------------------------------------------------------------------
#
# Description:
#     This script automates the conversion of Sigma rules to a specific output
#     format suitable for uberAgent.
#
#     The script traverses through a set of predefined Sigma rule directories,
#     converts the rules using the Sigma converter tool, and then writes the
#     converted rules to an output file. Each output file is named according
#     to the severity and platform of the rules it contains.
#
#     If an output file ends up containing no rules, it is automatically deleted.
#
# Usage:
#     ./convert-rules.sh <base_directory> [pipeline]
#
#     - <base_directory>: Mandatory. The absolute path to the base directory
#                         containing the Sigma rule directories.
#     - [pipeline]: Optional. Specifies the pipeline argument for the Sigma
#                   converter command. Defaults to 'uberagent' if not provided.
#
# Sigma Rule Directory Layout (requirement for this script):
#     The base directory should contain Sigma rule directories with the following naming convention:
#     - sigma-<severity>-<platform>/
#     where:
#       <severity>: Represents the severity of the rules (e.g., critical, high, medium, low, informational).
#       <platform>: Represents the platform for the rules (e.g., windows, macos, common).
#
#     Example:
#       - sigma-critical-windows/
#       - sigma-high-macos/
#       - sigma-medium-common/
#
# -----------------------------------------------------------------------------

# Check if base directory is provided
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <base_directory> [pipeline]"
    exit 1
fi

# Assign base directory from argument
BASE_DIR="$1"

# Define an associative array with source paths as keys and output files as values
declare -A configs=(
    ["sigma-critical"]="uberAgent-ESA-am-sigma-critical"
    ["sigma-high"]="uberAgent-ESA-am-sigma-high"
    ["sigma-informational"]="uberAgent-ESA-am-sigma-informational"
    ["sigma-low"]="uberAgent-ESA-am-sigma-low"
    ["sigma-medium"]="uberAgent-ESA-am-sigma-medium"
)

# Pattern and target are the same for all commands
TARGET="uberagent"

# Assign pipeline from second argument or default to "uberagent"
PIPELINE="${2:-uberagent}"

# Initialize an empty array to store summary messages
declare -a summaryMessages=()
declare -a summaryEmptyMessages=()

# Loop over the directories and run the sigma converter command
for dir in ${BASE_DIR}/*; do

    if [ -d "$dir" ]; then
        DIR_NAME=$(basename "$dir")
        OUTPUT_FILE="uberAgent-ESA-am-$DIR_NAME.conf"

        # Define the header
        HEADER="
#
# The rules are generated from the Sigma GitHub repository at https://github.com/SigmaHQ/sigma
# To generate the ruleset, please follow the instructions provided in the repository: https://github.com/vastlimits/pySigma-backend-uberAgent/
#
# The command used to generate the ruleset is:
#    sigma convert -s -f conf -p $PIPELINE -t $TARGET $dir >> $OUTPUT_FILE
#
"

        # Write the header to the output file
        echo -e "$HEADER" > "$OUTPUT_FILE"

        # Run the sigma converter command and append the output to the file
        sigma convert -s -f conf -p "$PIPELINE" -t "$TARGET" "$dir" >> "$OUTPUT_FILE"

        # echo "Conversion completed, output saved to $OUTPUT_FILE"

        # Count the occurrences of [ActivityMonitoringRule] in the output file
        RULE_COUNT=$(grep -o 'ActivityMonitoringRule' "$OUTPUT_FILE" | wc -l)

        # Check if the file contains 0 rules
        if [ $RULE_COUNT -eq 0 ]; then
            summaryEmptyMessages+=("File $OUTPUT_FILE contains 0 rules.")
        else
            summaryMessages+=("File $OUTPUT_FILE contains $RULE_COUNT rules.")
        fi
    fi
done

# Print the summary messages
echo -e "\nSummary:"
for message in "${summaryMessages[@]}"; do
    echo "$message"
done

echo -e "\nSummary (empty):"
for message in "${summaryEmptyMessages[@]}"; do
    echo "$message"
done
