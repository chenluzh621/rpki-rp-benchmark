#!/bin/sh

# ca1.crl's AKI contains the forbidden authorityCertIssuer field. BaRRy does
# not expose that field, so convert an equal-length DER sentinel and re-sign.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init

# RD encodes authorityCertSerialNumber as the six bytes
#   82 04 82 02 74 61
# where the four content bytes form GeneralNames { dNSName "ta" }.
# Change only the outer [2] primitive tag to the [1] constructed tag used by
# authorityCertIssuer. All DER lengths therefore remain unchanged.
perl - "$CRL" "$WORK/issuer-mutated.crl" <<'PERL'
use strict;
use warnings;

my ($input, $output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $crl = <$fh>;
close $fh;

my $needle = "\x82\x04\x82\x02ta";
my $count = 0;
my $position = -1;
my $search = 0;
while (($search = index($crl, $needle, $search)) >= 0) {
	$count++;
	$position = $search;
	$search++;
}
die "Expected one AKI sentinel, found $count\n" if $count != 1;
substr($crl, $position, 1, "\xa1");

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $crl;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot add authorityCertIssuer to ca1.crl"

extract_tbs_cert_list "$WORK/issuer-mutated.crl" "$WORK/tbs.der"
openssl dgst -sha256 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl"
replace_crl_signature "$WORK/issuer-mutated.crl" "$WORK/signature.bin" \
	"$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl crl -inform DER -in "$CRL" -text -noout \
	> "$WORK/crl.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
grep -Fq "DNS:ta" "$WORK/crl.txt" \
	|| fail "ca1.crl does not contain authorityCertIssuer dNSName ta"
openssl x509 -inform DER -in "$CA" -pubkey -noout > "$WORK/ca-public.pem"
openssl dgst -sha256 -verify "$WORK/ca-public.pem" \
	-signature "$WORK/signature.bin" "$WORK/tbs.der" \
	> "$WORK/verify.log" 2>&1 \
	|| fail "The re-signed ca1.crl does not verify"

publish_mutated_crl
run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
