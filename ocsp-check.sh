#!/bin/sh
# This script challenge all clients certificates during authentication with AWS OCSP server.
# If a certificate have been revoked, authentication will fail.
# Based on https://github.com/OpenVPN/openvpn/blob/master/contrib/OCSP_check/OCSP_check.sh

# OCSP responder URL (mandatory)
# Need to point to AWS region containing the AWS ACM PCA
ocsp_url="http://ocsp.acm-pca.us-east-1.amazonaws.com"

# Path to issuer certificate (mandatory)
# Where to find AWS ACMPCA CA file
issuer="/etc/openvpn/ca-chain.crt"
verify="/etc/openvpn/ca-chain.crt"
nonce="-nonce"

check_depth=0

cur_depth=$1   # this is the *CURRENT* depth from OpenVPN
common_name=$2 # CN

err=0
if [[ -z "$issuer" ]] || [[ ! -e "$issuer" ]]; then
  echo "Error: issuer certificate undefined or not found!" >&2
  err=1
fi

if [[ -z "$verify" ]] || [[ ! -e "$verify" ]]; then
  echo "Error: verification certificate undefined or not found!" >&2
  err=1
fi

if [[ -z "$ocsp_url" ]]; then
  echo "Error: OCSP server URL not defined!" >&2
  err=1
fi

if [[ $err -eq 1 ]]; then
  echo "Did you forget to customize the variables in the script?" >&2
  exit 1
fi

# begin
if [[ $check_depth -eq -1 ]] || [[ $cur_depth -eq $check_depth ]]; then
  eval serial="\$tls_serial_${cur_depth}"

  if [[ -n $serial ]]; then
    date=$(date +"%a %b %d %T %Y")
    status=$(openssl ocsp \
                    "$nonce" \
                    -verify_other "$issuer" \
                    -CAfile "$verify" \
                    -issuer "$issuer" \
                    -serial "${serial}" \
                    -url "$ocsp_url" \
                    -header "Host" "ocsp.acm-pca.us-east-1.amazonaws.com" 2>&1)
    if [[ $? -eq 0 ]]; then

      # check if ocsp didn't report any errors
      if echo "$status" | grep -Eq "(error|fail)"; then
          echo "$date [OCSP] $common_name authentication attempt with revoked certificate ($serial)"
          exit 1
      fi
      # check that the reported status of certificate is ok
      if echo "$status" | grep -Eq "^${serial}: good"; then
        # check if signature on the OCSP response verified correctly
        if echo "$status" | grep -Eq "^Response verify OK"; then
            # All good serial SSL cert is valid
            exit 0
        fi
      else
        cert_status=$(echo "$status" | grep -E "^${serial}:"| cut -d\  -f2)
        echo "$date [OCSP] $common_name OCSP certificate is invalid with status $cert_status ($serial)"
        exit 1
      fi
    fi
  fi
  echo "$date [OCSP] $common_name error while checking OCSP certificate validity ($serial)"
  exit 1
fi

