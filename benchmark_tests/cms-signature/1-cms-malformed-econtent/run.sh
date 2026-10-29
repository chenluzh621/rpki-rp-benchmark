#!/bin/sh

# Change the encapsulated ROA payload and its signed messageDigest after
# repository generation, but leave SignerInfo.signature untouched.  The
# digest binding therefore passes and verification fails at the EE signature.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

prepare_valid_roa

# In the baseline RouteOriginAttestation, AS64501 is DER INTEGER
# 02 03 00 fb f5.  Replace it with same-length AS64505 (02 03 00 fb f9),
# then replace the signed messageDigest with SHA-256(new eContent).  DER lengths
# stay unchanged, and the original 256-byte signature is deliberately retained.
perl - "$ROA" "$CMS_WORK/original-content.der" \
	"$CMS_WORK/mutated-content.der" <<'PERL'
use strict;
use warnings;
use Digest::SHA qw(sha256);

my ($roa_path, $content_path, $mutated_content_path) = @ARGV;

sub read_all {
	my ($path) = @_;
	open my $input, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}

sub write_all {
	my ($path, $data) = @_;
	open my $output, '>:raw', $path or die "Cannot write $path: $!\n";
	print {$output} $data;
	close $output;
}

my $roa = read_all($roa_path);
my $original_content = read_all($content_path);
my $mutated_content = $original_content;

my $old = pack('H*', '020300fbf5');
my $new = pack('H*', '020300fbf9');
my $as_count = ($mutated_content =~ s/\Q$old\E/$new/g);
die "Expected one AS64501 DER encoding, found $as_count\n"
	if $as_count != 1;

my $original_digest = sha256($original_content);
my $mutated_digest = sha256($mutated_content);

my $content_count = ($roa =~ s/\Q$original_content\E/$mutated_content/g);
die "Expected one encapsulated ROA content, found $content_count\n"
	if $content_count != 1;

my $digest_count = ($roa =~ s/\Q$original_digest\E/$mutated_digest/g);
die "Expected one signed messageDigest, found $digest_count\n"
	if $digest_count != 1;

write_all($roa_path, $roa);
write_all($mutated_content_path, $mutated_content);
PERL
test "$?" -eq 0 \
	|| fail "Cannot mutate roa1-1.roa eContent and messageDigest"

# Prove that the outer signature value is byte-for-byte unchanged.
tail -c 256 "$ROA" > "$CMS_WORK/mutated-signature.bin"
cmp -s "$CMS_WORK/original-signature.bin" \
	"$CMS_WORK/mutated-signature.bin" \
	|| fail "The eContent mutation unexpectedly changed the CMS signature"

# Decode without checking the signature and prove that the installed eContent
# is exactly the intended DER payload containing AS64505.
openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
	-out "$CMS_WORK/extracted-mutated-content.der" \
	> "$CMS_WORK/mutated-content-extract.log" 2>&1 \
	|| fail "Cannot extract the mutated ROA eContent"
cmp -s "$CMS_WORK/mutated-content.der" \
	"$CMS_WORK/extracted-mutated-content.der" \
	|| fail "The installed ROA eContent differs from the intended mutation"
openssl asn1parse -inform DER -in "$CMS_WORK/mutated-content.der" \
	> "$CMS_WORK/mutated-content-asn1.txt" 2>&1 \
	|| fail "The mutated ROA eContent is not valid DER"
grep -Eq 'INTEGER[[:space:]]+:FBF9$' \
	"$CMS_WORK/mutated-content-asn1.txt" \
	|| fail "The mutated ROA eContent does not contain AS64505"

assert_invalid_cms_signature

# Since messageDigest was updated to match eContent, OpenSSL must fail in
# SignerInfo signature verification rather than content-digest verification.
grep -Fq 'CMS_SignerInfo_verify:verification failure' \
	"$CMS_WORK/mutated-verify.log" \
	|| fail "CMS verification did not fail at the EE signature stage"
if grep -Eq 'CMS_SignerInfo_verify_content|content verify error' \
	"$CMS_WORK/mutated-verify.log"; then
	fail "CMS verification still failed at the messageDigest stage"
fi
publish_mutated_roa

run_rp
check_only_target_roa_rejected
