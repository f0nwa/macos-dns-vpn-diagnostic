#!/usr/bin/env bash

# Integrity helpers for macos-dns-test.sh

_dns_diag_log_err() {
  printf '%s\n' "$*" >&2
}

dns_diag_sha256_file() {
  local file_path="$1"
  shasum -a 256 "$file_path" | awk '{print $1}'
}

dns_diag_fetch_file() {
  local url="$1" out="$2"
  curl -fsSL "$url" -o "$out"
}

dns_diag_verify_checksum_record() {
  local script_path="$1" checksums_file="$2"
  local script_name expected actual

  script_name="$(basename "$script_path")"
  expected="$(awk -v n="$script_name" '
    {
      f=$2
      sub(/^\*+/, "", f)
      sub(/^\.\//, "", f)
      if (f==n) {
        print $1
        exit
      }
    }
  ' "$checksums_file")"

  if [ -z "$expected" ]; then
    _dns_diag_log_err "[integrity] checksum record not found for $script_name"
    return 1
  fi

  actual="$(dns_diag_sha256_file "$script_path")"
  if [ "$actual" != "$expected" ]; then
    _dns_diag_log_err "[integrity] checksum mismatch for $script_name"
    _dns_diag_log_err "[integrity] expected: $expected"
    _dns_diag_log_err "[integrity] actual:   $actual"
    return 1
  fi

  return 0
}

dns_diag_verify_minisign() {
  local checksums_file="$1" sig_file="$2" pubkey="$3"
  minisign -Vm "$checksums_file" -x "$sig_file" -P "$pubkey" >/dev/null 2>&1
}

dns_diag_verify_self() {
  local script_path="$1"
  local mode checksums_url sig_url pubkey tmp_dir checksums_file sig_file

  if [ "${DNS_DIAG_SKIP_INTEGRITY:-0}" = "1" ]; then
    return 0
  fi

  mode="${VERIFY_MODE:-soft}"
  checksums_url="${DNS_DIAG_CHECKSUMS_URL:-https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/checksums.txt}"
  sig_url="${DNS_DIAG_CHECKSUMS_SIG_URL:-https://raw.githubusercontent.com/f0nwa/macos-dns-vpn-diagnostic/main/checksums.txt.minisig}"
  pubkey="${DNS_DIAG_MINISIGN_PUBKEY:-}"

  tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t dnsdiag)"
  checksums_file="$tmp_dir/checksums.txt"
  sig_file="$tmp_dir/checksums.txt.minisig"

  if ! dns_diag_fetch_file "$checksums_url" "$checksums_file"; then
    _dns_diag_log_err "[integrity] failed to download checksums: $checksums_url"
    rm -rf "$tmp_dir"
    return 1
  fi

  if [ "$mode" = "strict" ]; then
    if ! command -v minisign >/dev/null 2>&1; then
      _dns_diag_log_err "[integrity] strict mode requires minisign"
      rm -rf "$tmp_dir"
      return 1
    fi
    if [ -z "$pubkey" ]; then
      _dns_diag_log_err "[integrity] strict mode requires DNS_DIAG_MINISIGN_PUBKEY"
      rm -rf "$tmp_dir"
      return 1
    fi
    if ! dns_diag_fetch_file "$sig_url" "$sig_file"; then
      _dns_diag_log_err "[integrity] strict mode requires signature file: $sig_url"
      rm -rf "$tmp_dir"
      return 1
    fi
    if ! dns_diag_verify_minisign "$checksums_file" "$sig_file" "$pubkey"; then
      _dns_diag_log_err "[integrity] minisign verification failed"
      rm -rf "$tmp_dir"
      return 1
    fi
  elif [ "$mode" = "soft" ]; then
    if command -v minisign >/dev/null 2>&1 && [ -n "$pubkey" ]; then
      if dns_diag_fetch_file "$sig_url" "$sig_file"; then
        if ! dns_diag_verify_minisign "$checksums_file" "$sig_file" "$pubkey"; then
          _dns_diag_log_err "[integrity] minisign signature invalid"
          rm -rf "$tmp_dir"
          return 1
        fi
      fi
    fi
  else
    _dns_diag_log_err "[integrity] unknown VERIFY_MODE=$mode"
    rm -rf "$tmp_dir"
    return 1
  fi

  if ! dns_diag_verify_checksum_record "$script_path" "$checksums_file"; then
    rm -rf "$tmp_dir"
    return 1
  fi

  rm -rf "$tmp_dir"
  return 0
}
