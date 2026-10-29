#!/bin/sh

# Change only ca1.crl's issuer CN string tag from PrintableString to
# UTF8String, then restore every signature/hash affected by that mutation.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init
ISSUER_CN=$(openssl crl -inform DER -in "$CRL" -issuer -noout \
	-nameopt RFC2253 | sed 's/^issuer=CN=//')
test -n "$ISSUER_CN" || fail "Cannot read ca1.crl's issuer CN"

# Locate the unique issuer CN PrintableString TLV and change only its tag.
perl - "$CRL" "$ISSUER_CN" "$WORK/tag-mutated.crl" <<'PERL'
use strict;
use warnings;

my ($input, $issuer_cn, $output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $crl = <$fh>;
close $fh;

my $needle = "\x13" . chr(length($issuer_cn)) . $issuer_cn;
my $count = 0;
my $position = -1;
my $search = 0;
while (($search = index($crl, $needle, $search)) >= 0) {
	$count++;
	$position = $search;
	$search++;
}
die "Expected one issuer PrintableString, found $count\n" if $count != 1;
substr($crl, $position, 1, "\x0c");

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $crl;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot change ca1.crl's issuer CN to UTF8String"

extract_tbs_cert_list "$WORK/tag-mutated.crl" "$WORK/tbs.der"
openssl dgst -sha256 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl"
replace_crl_signature "$WORK/tag-mutated.crl" "$WORK/signature.bin" \
	"$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl asn1parse -inform DER -in "$CRL" \
	> "$WORK/asn1.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
grep -Fq "UTF8STRING        :$ISSUER_CN" "$WORK/asn1.txt" \
	|| fail "ca1.crl's issuer CN is not a UTF8String"
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
