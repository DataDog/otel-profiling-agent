#!/usr/bin/env bash

# bash strict mode
set -euo pipefail
IFS=$'\n\t'

display_usage() {
	echo "Generate release notes for a release:"
	echo -e "\nUsage:\n generate_release_notes.sh [previous_tag] [new_tag] \n"
}

# check whether user had supplied -h or --help . If yes display usage
if [[ ( $# == "--help") ||  $# == "-h" ]]
then
	display_usage
	exit 0
fi

# if less than two arguments supplied, display usage
if [  $# -le 1 ] || [ $# -gt 2 ]
then
  echo -e "Incorrect number of arguments, expected 2 \n"
	display_usage
	exit 1
fi

PREVIOUS_TAG=$1
NEW_TAG=$2

# Verify that the tags are valid
if ! git rev-parse "${PREVIOUS_TAG}" >/dev/null 2>&1; then
  echo "Tag $PREVIOUS_TAG does not exist"
  exit 1
fi

if ! git rev-parse "${NEW_TAG}" >/dev/null 2>&1; then
  echo "Tag $NEW_TAG does not exist"
  exit 1
fi


#######################################
# Get the reference to upstream commits between the two tags
# Globals:
#   PREVIOUS_TAG
#   NEW_TAG
# Arguments:
#   None
# Outputs:
#   A string with the format "upstream_commit1...upstream_commit2" that can be used as a reference to the upstream commits between the two tags
#######################################
function get_upstream_diff() {
  local first_datadog_commit_name="Add options to control reporter interval / sampling frequency"

  local previous_first_datadog_commit
  previous_first_datadog_commit=$(git log "${PREVIOUS_TAG}" --grep="${first_datadog_commit_name}" --pretty=format:"%H" | tail -n 1)

  local new_first_datadog_commit
  new_first_datadog_commit=$(git log "${NEW_TAG}" --grep="${first_datadog_commit_name}" --pretty=format:"%H" | tail -n 1)

  local previous_upstream
  previous_upstream=$(git show -s --pretty=%P "${previous_first_datadog_commit}")

  local new_upstream
  new_upstream=$(git show -s --pretty=%P "${new_first_datadog_commit}"^1)

  echo "$previous_upstream...$new_upstream"
}

#######################################
# Get the reference to datadog commits between the two tags
# Globals:
#   PREVIOUS_TAG
#   NEW_TAG
# Arguments:
#   None
# Outputs:
#   A string with the format "commit1...commit2" that can be used as a reference to the upstream commits between the two tags
#######################################
function get_datadog_diff() {
  local previous_tag_last_commit
  previous_tag_last_commit=$(git rev-list -n 1 "${PREVIOUS_TAG}")

  local previous_tag_last_commit_name
  previous_tag_last_commit_name=$(git log -1 "${previous_tag_last_commit}" --pretty=%B | head -n+1)

  local new_tag_first_commit
  new_tag_first_commit=$(git log "${NEW_TAG}" --grep="${previous_tag_last_commit_name}" --pretty=format:"%H" | tail -n 1)

  local new_tag_commit
  new_tag_commit=$(git rev-list -n 1 "${NEW_TAG}")

  echo "${new_tag_first_commit}...${new_tag_commit}"
}

#######################################
# Print the release notes for the release
# Globals:
#   PREVIOUS_TAG
#   NEW_TAG
# Arguments:
#   None
# Outputs:
#   The release notes for the release
#######################################
function generate_release_notes() {
  local upstream_diff
  upstream_diff=$(get_upstream_diff)

  local datadog_diff
  datadog_diff=$(get_datadog_diff)

  echo "# Major updates"
  echo -e "\n"
  echo "* Updated upstream for otel-profiling-agent ${upstream_diff}"
  echo "* <...> fill in the major updates here <...>"
  echo -e "\n"

  echo "# Full changelog"
  echo "<details>"
  echo "<summary>Expand to see the full changelog</summary>"
  echo -e "\n"
  echo "### Upstream changes:"
  # get rid of PR number and just show the commit hash and message
  git log --pretty=format:"* %h %s" "${upstream_diff}" | cat | sed -E 's/\(#[0-9]+\)//g'
  echo -e "\n"
  echo "**Upstream Changelog**: [link](https://github.com/DataDog/otel-profiling-agent/compare/${upstream_diff})"
  echo -e "\n"
  echo "### Datadog changes:"
  git log --pretty=format:"* %h %s" "${datadog_diff}" | cat
  echo -e "\n"
  echo "**Datadog Changelog**: [link](https://github.com/DataDog/otel-profiling-agent/compare/${datadog_diff})"
  echo "</details>"
}

generate_release_notes
