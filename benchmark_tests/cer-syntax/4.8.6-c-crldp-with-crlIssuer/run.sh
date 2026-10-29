#!/bin/sh

# ca1.cer's sole DistributionPoint contains the forbidden cRLIssuer field.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.6-common.sh"

crldp_mutate_ca crl-issuer
crldp_check_rejected_branch
