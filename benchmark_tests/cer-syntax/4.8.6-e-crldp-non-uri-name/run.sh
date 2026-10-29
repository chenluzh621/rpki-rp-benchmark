#!/bin/sh

# ca1.cer's CRLDP fullName contains a dNSName instead of a URI.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.6-common.sh"

crldp_mutate_ca non-uri-name
crldp_check_rejected_branch
