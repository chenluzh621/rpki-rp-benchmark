#!/bin/sh

# Helpers for CRL mutations that BaRRy cannot express completely on its own.
. "$SRCDIR/../../der-decoding/common.sh"

crl_mutation_init() {
	CRL="sandbox/rsyncd/content/$TEST/ca1/ca1.crl"
	CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
	MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
	SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
	NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
	WORK="$SANDBOX/crl-update"

	# Re-signing requires BaRRy's deterministic test key pool.
	unset BARRY_GENERATE_KEYS
	run_barry
	mkdir -p "$WORK"

	ORIGINAL_CRL_HASH=$(sha256sum "$CRL" | cut -d' ' -f1)

	# A CRL is signed by its issuing CA. Find ca1.cer's matching private key.
	CA_KEY_HASH=$(openssl x509 -inform DER -in "$CA" -pubkey -noout \
		| openssl pkey -pubin -outform DER 2> /dev/null \
		| sha256sum | cut -d' ' -f1)
	CRL_KEY=""
	for KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		KEY_HASH=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER \
			2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$KEY_HASH" = "$CA_KEY_HASH"; then
			CRL_KEY="$KEY_FILE"
			break
		fi
	done
	test -n "$CRL_KEY" || fail "Cannot find ca1.cer's private key"
}

# Extract the complete DER-encoded TBSCertList from a CertificateList.
# $1: Input CRL
# $2: Output TBSCertList
extract_tbs_cert_list() {
	perl - "$1" "$2" <<'PERL'
use strict;
use warnings;

my ($input, $tbs_output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $crl = <$fh>;
close $fh;

sub tlv {
	my ($data, $offset) = @_;
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8) |
				ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	return ($header, $length, $header + $length);
}

my ($outer_header, undef, undef) = tlv($crl, 0);
my $tbs_offset = $outer_header;
die "TBSCertList is not a SEQUENCE\n"
	if ord(substr($crl, $tbs_offset, 1)) != 0x30;
my (undef, undef, $tbs_total) = tlv($crl, $tbs_offset);

open my $tbs, '>:raw', $tbs_output
	or die "Cannot open $tbs_output: $!\n";
print {$tbs} substr($crl, $tbs_offset, $tbs_total);
close $tbs;
PERL
	test "$?" -eq 0 || fail "Cannot extract ca1.crl's TBSCertList"
}

# Replace the outer signature BIT STRING without changing DER lengths.
# $1: Input CRL
# $2: Raw signature bytes
# $3: Output CRL
replace_crl_signature() {
	perl - "$1" "$2" "$3" <<'PERL'
use strict;
use warnings;

my ($crl_path, $sig_path, $output) = @ARGV;
sub read_all {
	my ($path) = @_;
	open my $fh, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}
sub tlv {
	my ($data, $offset) = @_;
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8) |
				ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	return ($header, $length, $header + $length);
}

my $crl = read_all($crl_path);
my $signature = read_all($sig_path);
my ($outer_header, undef, undef) = tlv($crl, 0);
my $offset = $outer_header;
for (1 .. 2) {
	my (undef, undef, $total) = tlv($crl, $offset);
	$offset += $total;
}
die "CRL signature is not a BIT STRING\n"
	if ord(substr($crl, $offset, 1)) != 0x03;
my ($sig_header, $sig_length, undef) = tlv($crl, $offset);
die "Unexpected unused-bits value\n"
	if ord(substr($crl, $offset + $sig_header, 1)) != 0;
die "New signature has the wrong size\n"
	if length($signature) != $sig_length - 1;
substr($crl, $offset + $sig_header + 1, length($signature), $signature);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $crl;
close $out;
PERL
	test "$?" -eq 0 || fail "Cannot install ca1.crl's new signature"
}

# Apply one deliberately invalid change to the first revoked-certificate entry.
# $1: Mutation: missing-serial, missing-date, or reason-code
# $2: Input CRL
# $3: Output CRL
mutate_first_crl_entry() {
	perl - "$1" "$2" "$3" <<'PERL'
use strict;
use warnings;

my ($mutation, $input, $output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $crl = <$fh>;
close $fh;

sub tlv {
	my ($data, $offset) = @_;
	die "Truncated DER tag\n" if $offset + 2 > length($data);
	my $tag = ord(substr($data, $offset, 1));
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		die "Truncated DER length\n" if $offset + 2 + $count > length($data);
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8) |
				ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	die "Truncated DER value\n"
		if $offset + $header + $length > length($data);
	return ($tag, $header, $length, $header + $length);
}

sub children {
	my ($data, $offset, $wanted_tag) = @_;
	my ($tag, $header, $length, undef) = tlv($data, $offset);
	die sprintf("Expected tag 0x%02x, found 0x%02x\n", $wanted_tag, $tag)
		if $tag != $wanted_tag;
	my $at = $offset + $header;
	my $end = $at + $length;
	my @result;
	while ($at < $end) {
		my (undef, undef, undef, $total) = tlv($data, $at);
		push @result, $at;
		$at += $total;
	}
	die "DER child extends past its parent\n" if $at != $end;
	return ($offset + $header, $end, @result);
}

sub der_length {
	my ($length) = @_;
	return chr($length) if $length < 128;
	my $encoded = '';
	while ($length > 0) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub sequence {
	my ($content) = @_;
	return "\x30" . der_length(length($content)) . $content;
}

sub replace_child {
	my ($data, $parent_offset, $child_offset, $replacement) = @_;
	my (undef, $parent_header, $parent_length, undef) =
		tlv($data, $parent_offset);
	my (undef, undef, undef, $child_total) = tlv($data, $child_offset);
	my $content_start = $parent_offset + $parent_header;
	my $content_end = $content_start + $parent_length;
	my $content = substr($data, $content_start,
		$child_offset - $content_start)
		. $replacement
		. substr($data, $child_offset + $child_total,
			$content_end - $child_offset - $child_total);
	return sequence($content);
}

my (undef, undef, @outer_children) = children($crl, 0, 0x30);
die "CertificateList does not contain three fields\n"
	if @outer_children != 3;
my $tbs_offset = $outer_children[0];
my (undef, undef, @tbs_children) = children($crl, $tbs_offset, 0x30);

# Skip version, signature, issuer, thisUpdate and optional nextUpdate.
my $index = 0;
my ($tag) = tlv($crl, $tbs_children[$index]);
$index++ if $tag == 0x02;
$index += 2;
($tag) = tlv($crl, $tbs_children[$index]);
die "TBSCertList lacks thisUpdate\n" if $tag != 0x17 && $tag != 0x18;
$index++;
($tag) = tlv($crl, $tbs_children[$index]);
$index++ if $tag == 0x17 || $tag == 0x18;
die "TBSCertList lacks revokedCertificates\n"
	if $index >= @tbs_children;
my $revoked_offset = $tbs_children[$index];

my (undef, undef, @entries) = children($crl, $revoked_offset, 0x30);
die "revokedCertificates is empty\n" if !@entries;
my $entry_offset = $entries[0];
my ($entry_start, $entry_end, @entry_children) =
	children($crl, $entry_offset, 0x30);
die "Expected a plain CRL entry with serial number and revocation date\n"
	if @entry_children != 2;
my ($serial_tag, undef, undef, $serial_total) =
	tlv($crl, $entry_children[0]);
my ($date_tag, undef, undef, $date_total) =
	tlv($crl, $entry_children[1]);
die "First CRL entry field is not an INTEGER\n" if $serial_tag != 0x02;
die "Second CRL entry field is not a Time\n"
	if $date_tag != 0x17 && $date_tag != 0x18;

my $entry_content;
if ($mutation eq 'missing-serial') {
	$entry_content = substr($crl, $entry_children[1], $date_total);
} elsif ($mutation eq 'missing-date') {
	$entry_content = substr($crl, $entry_children[0], $serial_total);
} elsif ($mutation eq 'reason-code') {
	# Extensions ::= SEQUENCE OF Extension. reasonCode's extnValue contains
	# the DER ENUMERATED value keyCompromise (1).
	my $reason_code = "\x30\x0c\x30\x0a\x06\x03\x55\x1d\x15"
		. "\x04\x03\x0a\x01\x01";
	$entry_content = substr($crl, $entry_start, $entry_end - $entry_start)
		. $reason_code;
} else {
	die "Unknown CRL-entry mutation '$mutation'\n";
}

my $new_entry = sequence($entry_content);
my $new_revoked = replace_child($crl, $revoked_offset,
	$entry_offset, $new_entry);
my $new_tbs = replace_child($crl, $tbs_offset,
	$revoked_offset, $new_revoked);
my $new_crl = replace_child($crl, 0, $tbs_offset, $new_tbs);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $new_crl;
close $out;
PERL
	test "$?" -eq 0 || fail "Cannot mutate ca1.crl's first entry"
}

# Publish the changed CRL while keeping the manifest and RRDP metadata valid.
publish_mutated_crl() {
	MUTATED_CRL_HASH=$(sha256sum "$CRL" | cut -d' ' -f1)
	rehash_and_resign_manifest \
		"$MANIFEST" "$ORIGINAL_CRL_HASH" "$MUTATED_CRL_HASH"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/ca1.crl" "$CRL"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
	realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"
}
