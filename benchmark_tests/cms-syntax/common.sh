#!/bin/sh

# Mutate only SignedData.digestAlgorithms in the generated roa1-1.roa.
# The caller must source cms-signature/common.sh and call prepare_valid_roa
# first so ROA, CMS_WORK, and the original eContent are available.
mutate_signed_data_digest_algorithms() {
	DIGEST_MUTATION="$1"

	perl - "$ROA" "$DIGEST_MUTATION" <<'PERL'
use strict;
use warnings;

my ($path, $mutation) = @ARGV;

sub read_all {
	my ($file) = @_;
	open my $input, '<:raw', $file or die "Cannot open $file: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}

sub write_all {
	my ($file, $data) = @_;
	open my $output, '>:raw', $file or die "Cannot write $file: $!\n";
	print {$output} $data;
	close $output;
}

sub der_length {
	my ($length) = @_;
	return chr($length) if $length < 0x80;
	my $encoded = '';
	while ($length) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub tlv {
	my ($tag, $value) = @_;
	return chr($tag) . der_length(length($value)) . $value;
}

sub parse_one {
	my ($data, $offset) = @_;
	die "Missing DER tag at offset $offset\n" if $offset >= length($data);
	my $start = $offset;
	my $tag = ord(substr($data, $offset++, 1));
	die "High-tag-number DER is not supported\n" if ($tag & 0x1f) == 0x1f;
	die "Missing DER length at offset $offset\n" if $offset >= length($data);
	my $first = ord(substr($data, $offset++, 1));
	my $length;
	if (($first & 0x80) == 0) {
		$length = $first;
	} else {
		my $octets = $first & 0x7f;
		die "Indefinite or oversized DER length\n"
			if $octets == 0 || $octets > 4 || $offset + $octets > length($data);
		$length = 0;
		for (1 .. $octets) {
			$length = ($length << 8) | ord(substr($data, $offset++, 1));
		}
	}
	die "DER value overruns its container\n" if $offset + $length > length($data);
	my $value = substr($data, $offset, $length);
	my $end = $offset + $length;
	return {
		tag => $tag,
		value => $value,
		full => substr($data, $start, $end - $start),
		end => $end,
	};
}

sub parse_all {
	my ($data) = @_;
	my @values;
	my $offset = 0;
	while ($offset < length($data)) {
		my $value = parse_one($data, $offset);
		push @values, $value;
		$offset = $value->{end};
	}
	return @values;
}

my $sha256_oid = tlv(0x06, pack('H*', '608648016503040201'));
my $sha512_oid = tlv(0x06, pack('H*', '608648016503040203'));

my $roa = read_all($path);
my $content_info = parse_one($roa, 0);
die "ContentInfo is not one complete SEQUENCE\n"
	if $content_info->{tag} != 0x30 || $content_info->{end} != length($roa);

my @content_info_fields = parse_all($content_info->{value});
die "Unexpected ContentInfo field layout\n"
	if @content_info_fields != 2 || $content_info_fields[0]->{tag} != 0x06
	|| $content_info_fields[1]->{tag} != 0xa0;

my $signed_data = parse_one($content_info_fields[1]->{value}, 0);
die "SignedData is not one complete SEQUENCE\n"
	if $signed_data->{tag} != 0x30
	|| $signed_data->{end} != length($content_info_fields[1]->{value});

my @signed_data_fields = parse_all($signed_data->{value});
die "Unexpected SignedData prefix\n"
	if @signed_data_fields < 2 || $signed_data_fields[0]->{tag} != 0x02
	|| $signed_data_fields[1]->{tag} != 0x31;

my @algorithms = parse_all($signed_data_fields[1]->{value});
die "Expected exactly one original digest AlgorithmIdentifier\n"
	if @algorithms != 1 || $algorithms[0]->{tag} != 0x30;
my @algorithm_fields = parse_all($algorithms[0]->{value});
die "The original digest algorithm is not SHA-256\n"
	if !@algorithm_fields || $algorithm_fields[0]->{full} ne $sha256_oid;

my $new_digest_algorithms;
if ($mutation eq 'multiple') {
	# Duplicate the valid SHA-256 AlgorithmIdentifier so cardinality is the
	# only violation; the SET contains no unsupported algorithm.
	$new_digest_algorithms = tlv(0x31,
		$algorithms[0]->{full} . $algorithms[0]->{full});
} elsif ($mutation eq 'illegal') {
	# Keep the SET cardinality at one and replace only id-sha256 with
	# id-sha512, which is not allowed by the RPKI CMS profile.
	my $new_algorithm_value = $sha512_oid
		. join('', map { $_->{full} } @algorithm_fields[1 .. $#algorithm_fields]);
	$new_digest_algorithms = tlv(0x31, tlv(0x30, $new_algorithm_value));
} else {
	die "Unknown digestAlgorithms mutation '$mutation'\n";
}

$signed_data_fields[1] = {
	full => $new_digest_algorithms,
};
my $new_signed_data = tlv(0x30,
	join('', map { $_->{full} } @signed_data_fields));
my $new_explicit_content = tlv(0xa0, $new_signed_data);
my $new_content_info = tlv(0x30,
	$content_info_fields[0]->{full} . $new_explicit_content);

# Parse the rebuilt hierarchy and prove the exact intended mutation.
my $check_ci = parse_one($new_content_info, 0);
my @check_ci_fields = parse_all($check_ci->{value});
my $check_sd = parse_one($check_ci_fields[1]->{value}, 0);
my @check_sd_fields = parse_all($check_sd->{value});
my @check_algorithms = parse_all($check_sd_fields[1]->{value});
if ($mutation eq 'multiple') {
	die "Expected two mutated digest algorithms\n" if @check_algorithms != 2;
	for my $algorithm (@check_algorithms) {
		my @fields = parse_all($algorithm->{value});
		die "A duplicated digest algorithm is not SHA-256\n"
			if !@fields || $fields[0]->{full} ne $sha256_oid;
	}
} else {
	die "Expected one mutated digest algorithm\n" if @check_algorithms != 1;
	my @fields = parse_all($check_algorithms[0]->{value});
	die "The mutated digest algorithm is not SHA-512\n"
		if !@fields || $fields[0]->{full} ne $sha512_oid;
}

write_all($path, $new_content_info);
PERL
	test "$?" -eq 0 \
		|| fail "Cannot apply $DIGEST_MUTATION digestAlgorithms mutation"

	openssl asn1parse -inform DER -in "$ROA" \
		> "$CMS_WORK/digest-algorithms-asn1.txt" 2>&1 \
		|| fail "The mutated digestAlgorithms ROA is not valid DER"

	# No eContent or signed attribute is changed by this mutation. Extract
	# without signature checks and compare the payload to the valid baseline.
	openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
		-out "$CMS_WORK/mutated-content.der" \
		> "$CMS_WORK/mutated-content-extract.log" 2>&1 \
		|| fail "Cannot extract eContent after digestAlgorithms mutation"
	cmp -s "$CMS_WORK/original-content.der" "$CMS_WORK/mutated-content.der" \
		|| fail "digestAlgorithms mutation unexpectedly changed ROA eContent"
}

# Structurally mutate one optional SignedData field while preserving all other
# encoded fields byte-for-byte. Arguments: CMS path, mutation, optional CRL.
mutate_signed_data_optional_fields() {
	CMS_OBJECT="$1"
	CMS_MUTATION="$2"
	CMS_CRL="$3"

	perl - "$CMS_OBJECT" "$CMS_MUTATION" "$CMS_CRL" <<'PERL'
use strict;
use warnings;

my ($path, $mutation, $crl_path) = @ARGV;

sub read_all {
	my ($file) = @_;
	open my $input, '<:raw', $file or die "Cannot open $file: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}

sub write_all {
	my ($file, $data) = @_;
	open my $output, '>:raw', $file or die "Cannot write $file: $!\n";
	print {$output} $data;
	close $output;
}

sub der_length {
	my ($length) = @_;
	return chr($length) if $length < 0x80;
	my $encoded = '';
	while ($length) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub tlv {
	my ($tag, $value) = @_;
	return chr($tag) . der_length(length($value)) . $value;
}

sub parse_one {
	my ($data, $offset) = @_;
	die "Missing DER tag at offset $offset\n" if $offset >= length($data);
	my $start = $offset;
	my $tag = ord(substr($data, $offset++, 1));
	die "High-tag-number DER is not supported\n" if ($tag & 0x1f) == 0x1f;
	die "Missing DER length at offset $offset\n" if $offset >= length($data);
	my $first = ord(substr($data, $offset++, 1));
	my $length;
	if (($first & 0x80) == 0) {
		$length = $first;
	} else {
		my $octets = $first & 0x7f;
		die "Indefinite or oversized DER length\n"
			if $octets == 0 || $octets > 4 || $offset + $octets > length($data);
		$length = 0;
		for (1 .. $octets) {
			$length = ($length << 8) | ord(substr($data, $offset++, 1));
		}
	}
	die "DER value overruns its container\n" if $offset + $length > length($data);
	my $value = substr($data, $offset, $length);
	my $end = $offset + $length;
	return {
		tag => $tag,
		value => $value,
		full => substr($data, $start, $end - $start),
		end => $end,
	};
}

sub parse_all {
	my ($data) = @_;
	my @values;
	my $offset = 0;
	while ($offset < length($data)) {
		my $value = parse_one($data, $offset);
		push @values, $value;
		$offset = $value->{end};
	}
	return @values;
}

sub decode_signed_data {
	my ($cms) = @_;
	my $content_info = parse_one($cms, 0);
	die "ContentInfo is not one complete SEQUENCE\n"
		if $content_info->{tag} != 0x30 || $content_info->{end} != length($cms);
	my @content_info_fields = parse_all($content_info->{value});
	die "Unexpected ContentInfo field layout\n"
		if @content_info_fields != 2 || $content_info_fields[0]->{tag} != 0x06
		|| $content_info_fields[1]->{tag} != 0xa0;
	my $signed_data = parse_one($content_info_fields[1]->{value}, 0);
	die "SignedData is not one complete SEQUENCE\n"
		if $signed_data->{tag} != 0x30
		|| $signed_data->{end} != length($content_info_fields[1]->{value});
	my @signed_data_fields = parse_all($signed_data->{value});
	return ($content_info_fields[0]->{full}, @signed_data_fields);
}

my $cms = read_all($path);
my ($content_type, @signed_data_fields) = decode_signed_data($cms);
die "Unexpected baseline SignedData layout\n"
	if @signed_data_fields != 5
	|| $signed_data_fields[0]->{tag} != 0x02
	|| $signed_data_fields[1]->{tag} != 0x31
	|| $signed_data_fields[2]->{tag} != 0x30
	|| $signed_data_fields[3]->{tag} != 0xa0
	|| $signed_data_fields[4]->{tag} != 0x31;

my @certificates = parse_all($signed_data_fields[3]->{value});
die "Expected exactly one original certificate\n"
	if @certificates != 1 || $certificates[0]->{tag} != 0x30;

my $crl;
if ($mutation eq 'certificates-missing') {
	splice @signed_data_fields, 3, 1;
} elsif ($mutation eq 'certificates-multiple') {
	$signed_data_fields[3] = {
		full => tlv(0xa0, $certificates[0]->{full} . $certificates[0]->{full}),
	};
} elsif ($mutation eq 'crls-add') {
	die "A CRL path is required\n" if !defined($crl_path) || $crl_path eq '';
	$crl = read_all($crl_path);
	my $parsed_crl = parse_one($crl, 0);
	die "CRL is not one complete SEQUENCE\n"
		if $parsed_crl->{tag} != 0x30 || $parsed_crl->{end} != length($crl);
	# RevocationInfoChoices is [1] IMPLICIT SET OF RevocationInfoChoice.
	splice @signed_data_fields, 4, 0, { full => tlv(0xa1, $crl) };
} else {
	die "Unknown SignedData mutation '$mutation'\n";
}

my $new_signed_data = tlv(0x30,
	join('', map { $_->{full} } @signed_data_fields));
my $new_content_info = tlv(0x30,
	$content_type . tlv(0xa0, $new_signed_data));

# Parse the rebuilt hierarchy and prove the intended field cardinality.
my (undef, @check_fields) = decode_signed_data($new_content_info);
if ($mutation eq 'certificates-missing') {
	die "The certificates field still exists\n"
		if grep { $_->{tag} == 0xa0 } @check_fields;
} elsif ($mutation eq 'certificates-multiple') {
	my @check_certificates = parse_all($check_fields[3]->{value});
	die "Expected two certificates\n" if @check_certificates != 2;
	die "The duplicated certificates differ\n"
		if $check_certificates[0]->{full} ne $check_certificates[1]->{full};
} else {
	my @crl_fields = grep { $_->{tag} == 0xa1 } @check_fields;
	die "Expected one crls field\n" if @crl_fields != 1;
	my @check_crls = parse_all($crl_fields[0]->{value});
	die "The crls field does not contain the intended CRL\n"
		if @check_crls != 1 || $check_crls[0]->{full} ne $crl;
}

write_all($path, $new_content_info);
PERL
	test "$?" -eq 0 || fail "Cannot apply $CMS_MUTATION to $CMS_OBJECT"
}
