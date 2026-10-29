#!/bin/sh

# Corrupt only the signed messageDigest after repository generation.  The
# encapsulated ROA payload and SignerInfo.signature both stay byte-for-byte
# unchanged.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

prepare_valid_roa

# Locate messageDigest by hashing the extracted eContent, then flip one bit in
# the first digest byte.  Require exactly one match so no other field can be
# changed silently.
perl - "$ROA" "$CMS_WORK/original-content.der" <<'PERL'
use strict;
use warnings;
use Digest::SHA qw(sha256);

my ($roa_path, $content_path) = @ARGV;

sub read_all {
	my ($path) = @_;
	open my $input, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}

my $roa = read_all($roa_path);
my $content = read_all($content_path);
my $original_digest = sha256($content);
my $wrong_digest = $original_digest;
substr($wrong_digest, 0, 1) =
	chr(ord(substr($wrong_digest, 0, 1)) ^ 0x01);

my $count = ($roa =~ s/\Q$original_digest\E/$wrong_digest/g);
die "Expected one signed messageDigest, found $count\n" if $count != 1;

open my $output, '>:raw', $roa_path
	or die "Cannot write $roa_path: $!\n";
print {$output} $roa;
close $output;
PERL
test "$?" -eq 0 || fail "Cannot mutate roa1-1.roa messageDigest"

# The complete CMS object must differ at exactly one byte.
cmp -l "$CMS_WORK/original.roa" "$ROA" > "$CMS_WORK/file-diff.txt"
test "$(wc -l < "$CMS_WORK/file-diff.txt")" -eq 1 \
	|| fail "The messageDigest mutation changed more than one ROA byte"

# Prove that SignerInfo.signature is unchanged.
tail -c 256 "$ROA" > "$CMS_WORK/mutated-signature.bin"
cmp -s "$CMS_WORK/original-signature.bin" \
	"$CMS_WORK/mutated-signature.bin" \
	|| fail "The messageDigest mutation unexpectedly changed the CMS signature"

# Decode without signature checks and prove that eContent is unchanged.
openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
	-out "$CMS_WORK/mutated-content.der" \
	> "$CMS_WORK/mutated-content-extract.log" 2>&1 \
	|| fail "Cannot extract eContent after the messageDigest mutation"
cmp -s "$CMS_WORK/original-content.der" "$CMS_WORK/mutated-content.der" \
	|| fail "The messageDigest mutation unexpectedly changed ROA eContent"

assert_invalid_cms_signature
publish_mutated_roa

run_rp
check_only_target_roa_rejected
