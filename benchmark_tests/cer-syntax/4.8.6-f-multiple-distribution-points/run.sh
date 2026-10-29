#!/bin/sh

# ca1.cer's CRLDP contains two DistributionPoint values.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.6-common.sh"

crldp_mutate_ca multiple-points
crldp_check_rejected_branch
