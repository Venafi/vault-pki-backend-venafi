#!/usr/bin/env bash
cert=$1
echo "##########################"
echo ""
echo "Checking certificate $cert"
echo ""
echo "##########################"
openssl x509 -in $cert -text -noout -certopt no_header,no_version,no_serial,no_signame,no_pubkey,no_sigdump,no_aux||echo -e "\n!!!!Can't decode certificate.!!!!\n"