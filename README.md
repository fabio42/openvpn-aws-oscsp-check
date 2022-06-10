# openvpn-aws-oscsp-check

This is a simple and small `ocsp-check.sh` scritpt to use with openvpn and query certificate validity with AWS provided ACMPCA OCSP server.

The only requirement is to rely on AWS ACMPCA as your PKI for the OpenVPN setup and enable this script with the following in openvpn `server.conf`:

```
# OCSP clients checks script
script-security 2
tls-verify /opt/bin/ocsp_check.sh
```
