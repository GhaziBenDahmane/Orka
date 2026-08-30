#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 IMAGE@sha256:DIGEST" >&2
  exit 2
fi

LC_ALL=C awk -v reference="$1" '
function invalid() { exit 1 }
function valid_port(value) {
  return value ~ /^[0-9]+$/ && value + 0 >= 1 && value + 0 <= 65535
}
function valid_dns(host, labels, count, i) {
  if (length(host) < 1 || length(host) > 253) return 0
  count = split(host, labels, ".")
  for (i = 1; i <= count; i++) {
    if (length(labels[i]) < 1 || length(labels[i]) > 63 || labels[i] !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) return 0
  }
  return 1
}
function valid_ipv6(host, groups, count, compressed, i, nonempty) {
  if (host !~ /^[0-9A-Fa-f:]+$/ || index(host, ":::") > 0) return 0
  compressed = index(host, "::") > 0
  if (compressed && index(substr(host, index(host, "::") + 2), "::") > 0) return 0
  count = split(host, groups, ":")
  nonempty = 0
  for (i = 1; i <= count; i++) {
    if (groups[i] == "") continue
    if (length(groups[i]) > 4 || groups[i] !~ /^[0-9A-Fa-f]+$/) return 0
    nonempty++
  }
  return compressed ? nonempty < 8 : nonempty == 8
}
function valid_authority(authority, bracket_end, host, suffix, colon, port) {
  if (substr(authority, 1, 1) == "[") {
    bracket_end = index(authority, "]")
    if (bracket_end < 4) return 0
    host = substr(authority, 2, bracket_end - 2)
    if (!valid_ipv6(host)) return 0
    suffix = substr(authority, bracket_end + 1)
    return suffix == "" || (substr(suffix, 1, 1) == ":" && valid_port(substr(suffix, 2)))
  }
  colon = index(authority, ":")
  if (colon > 0) {
    if (index(substr(authority, colon + 1), ":") > 0) return 0
    host = substr(authority, 1, colon - 1)
    port = substr(authority, colon + 1)
    if (!valid_port(port)) return 0
  } else host = authority
  return valid_dns(host)
}
BEGIN {
  if (reference == "" || reference ~ /[[:space:]]/) invalid()
  count = split(reference, at, "@")
  if (count != 2 || at[2] !~ /^sha256:[a-f0-9]+$/ || length(at[2]) != 71) invalid()
  name = at[1]
  last_slash = last_colon = 0
  for (i = 1; i <= length(name); i++) {
    character = substr(name, i, 1)
    if (character == "/") last_slash = i
    else if (character == ":") last_colon = i
  }
  repository = name
  if (last_colon > last_slash) {
    tag = substr(name, last_colon + 1)
    repository = substr(name, 1, last_colon - 1)
    if (tag !~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/ || length(tag) > 128) invalid()
  }
  if (repository == "" || length(repository) > 255) invalid()
  component_count = split(repository, components, "/")
  first = components[1]
  explicit_registry = tolower(first) == "localhost" || first ~ /[.:]/ || substr(first, 1, 1) == "["
  path_start = explicit_registry ? 2 : 1
  if (explicit_registry && (component_count < 2 || !valid_authority(first))) invalid()
  for (i = path_start; i <= component_count; i++) {
    component = components[i]
    if (length(component) < 1 || length(component) > 255 || component !~ /^[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*$/) invalid()
  }
  exit 0
}
' </dev/null
