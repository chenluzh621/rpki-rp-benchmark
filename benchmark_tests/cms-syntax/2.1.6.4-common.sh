#!/bin/sh

# Shared construction for SignerInfo.signedAttrs membership tests. BaRRy does
# not currently expose the attribute set through RD, so mutate its DER and
# re-sign the changed SignedAttributes with the original ROA EE private key.
. "$SRCDIR/../../cms-signature/common.sh"

prepare_roa_with_signed_attrs_mutation() {
	SIGNED_ATTRS_MUTATION="$1"
	prepare_valid_roa

	SIGNED_ATTRS_WORK="$CMS_WORK/signed-attrs"
	mkdir -p "$SIGNED_ATTRS_WORK"

	perl - "$ROA" "$SIGNED_ATTRS_MUTATION" \
		"$SIGNED_ATTRS_WORK/to-sign.der" <<'PERL'
use strict;
use warnings;

my ($path, $mutation, $sign_input_path) = @ARGV;

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
			if $octets == 0 || $octets > 4
			|| $offset + $octets > length($data);
		$length = 0;
		for (1 .. $octets) {
			$length = ($length << 8) | ord(substr($data, $offset++, 1));
		}
	}
	die "DER value overruns its container\n"
		if $offset + $length > length($data);
	my $end = $offset + $length;
	return {
		tag => $tag,
		value => substr($data, $offset, $length),
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

sub attribute_oid_hex {
	my ($attribute) = @_;
	die "Signed attribute is not a SEQUENCE\n" if $attribute->{tag} != 0x30;
	my @fields = parse_all($attribute->{value});
	die "Signed attribute does not begin with an OID\n"
		if !@fields || $fields[0]->{tag} != 0x06;
	return unpack('H*', $fields[0]->{value});
}

my %required = (
	'missing-content-type' => '2a864886f70d010903',
	'missing-message-digest' => '2a864886f70d010904',
	'missing-signing-time' => '2a864886f70d010905',
);
my $extra_oid = '2a0304'; # 1.2.3.4: not allowed by the RPKI CMS profile.

my $roa = read_all($path);
my $content_info = parse_one($roa, 0);
die "ContentInfo is not one complete SEQUENCE\n"
	if $content_info->{tag} != 0x30 || $content_info->{end} != length($roa);
my @content_info_fields = parse_all($content_info->{value});
die "Unexpected ContentInfo layout\n"
	if @content_info_fields != 2 || $content_info_fields[1]->{tag} != 0xa0;

my $signed_data = parse_one($content_info_fields[1]->{value}, 0);
die "SignedData is not one complete SEQUENCE\n"
	if $signed_data->{tag} != 0x30
	|| $signed_data->{end} != length($content_info_fields[1]->{value});
my @signed_data_fields = parse_all($signed_data->{value});
die "SignedData does not end with signerInfos\n"
	if !@signed_data_fields || $signed_data_fields[-1]->{tag} != 0x31;

my @signer_infos = parse_all($signed_data_fields[-1]->{value});
die "Expected exactly one SignerInfo\n"
	if @signer_infos != 1 || $signer_infos[0]->{tag} != 0x30;
my @signer_info_fields = parse_all($signer_infos[0]->{value});
my @signed_attrs_indexes = grep {
	$signer_info_fields[$_]->{tag} == 0xa0
} 0 .. $#signer_info_fields;
die "Expected exactly one signedAttrs field\n" if @signed_attrs_indexes != 1;
my $signed_attrs_index = $signed_attrs_indexes[0];
my @attributes = parse_all($signer_info_fields[$signed_attrs_index]->{value});

for my $oid (values %required) {
	my $count = grep { attribute_oid_hex($_) eq $oid } @attributes;
	die "Expected one required signed attribute $oid, found $count\n"
		if $count != 1;
}

if (exists $required{$mutation}) {
	my $target = $required{$mutation};
	@attributes = grep { attribute_oid_hex($_) ne $target } @attributes;
	die "Failed to remove signed attribute $target\n"
		if grep { attribute_oid_hex($_) eq $target } @attributes;
} elsif ($mutation eq 'not-allowed') {
	die "Unexpected pre-existing test attribute\n"
		if grep { attribute_oid_hex($_) eq $extra_oid } @attributes;
	my $extra_attribute = tlv(0x30,
		tlv(0x06, pack('H*', $extra_oid)) . tlv(0x31, tlv(0x05, '')));
	push @attributes, parse_one($extra_attribute, 0);
} elsif ($mutation eq 'duplicate-content-type') {
	my $content_type_oid = $required{'missing-content-type'};
	my @content_type_attributes = grep {
		attribute_oid_hex($_) eq $content_type_oid
	} @attributes;
	die "Expected one content-type attribute before duplication\n"
		if @content_type_attributes != 1;
	push @attributes, parse_one($content_type_attributes[0]->{full}, 0);
} elsif ($mutation eq 'content-type-multiple-values') {
	my $content_type_oid = $required{'missing-content-type'};
	my @indexes = grep {
		attribute_oid_hex($attributes[$_]) eq $content_type_oid
	} 0 .. $#attributes;
	die "Expected one content-type attribute before adding a value\n"
		if @indexes != 1;
	my $index = $indexes[0];
	my @fields = parse_all($attributes[$index]->{value});
	die "Unexpected content-type Attribute layout\n"
		if @fields != 2 || $fields[0]->{tag} != 0x06
		|| $fields[1]->{tag} != 0x31;
	my @values = parse_all($fields[1]->{value});
	die "Expected one original content-type attrValue\n" if @values != 1;
	my $multiple_values = tlv(0x31,
		$values[0]->{full} . $values[0]->{full});
	my $new_attribute = tlv(0x30, $fields[0]->{full} . $multiple_values);
	$attributes[$index] = parse_one($new_attribute, 0);
} else {
	die "Unknown signedAttrs mutation '$mutation'\n";
}

# SignedAttributes is a SET OF, so DER requires lexicographic ordering.
@attributes = sort { $a->{full} cmp $b->{full} } @attributes;
my $new_attributes_value = join('', map { $_->{full} } @attributes);
$signer_info_fields[$signed_attrs_index] = {
	full => tlv(0xa0, $new_attributes_value),
};

# CMS signs the DER SET OF encoding, not the IMPLICIT [0] tag stored in the
# SignerInfo structure.
write_all($sign_input_path, tlv(0x31, $new_attributes_value));

my $new_signer_info = tlv(0x30,
	join('', map { $_->{full} } @signer_info_fields));
$signed_data_fields[-1] = { full => tlv(0x31, $new_signer_info) };
my $new_signed_data = tlv(0x30,
	join('', map { $_->{full} } @signed_data_fields));
$content_info_fields[1] = { full => tlv(0xa0, $new_signed_data) };
my $new_content_info = tlv(0x30,
	join('', map { $_->{full} } @content_info_fields));
write_all($path, $new_content_info);
PERL
	test "$?" -eq 0 || fail "Cannot apply $SIGNED_ATTRS_MUTATION mutation"

	SIGNED_ATTRS_EE_KEY_HASH=$(openssl x509 -in "$CMS_WORK/ee.pem" \
		-pubkey -noout | openssl pkey -pubin -outform DER 2> /dev/null \
		| sha256sum | cut -d' ' -f1)
	SIGNED_ATTRS_EE_KEY=""
	for SIGNED_ATTRS_KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		SIGNED_ATTRS_KEY_HASH=$(openssl pkey -in "$SIGNED_ATTRS_KEY_FILE" \
			-pubout -outform DER 2> /dev/null \
			| sha256sum | cut -d' ' -f1)
		if test "$SIGNED_ATTRS_KEY_HASH" = "$SIGNED_ATTRS_EE_KEY_HASH"; then
			SIGNED_ATTRS_EE_KEY="$SIGNED_ATTRS_KEY_FILE"
			break
		fi
	done
	test -n "$SIGNED_ATTRS_EE_KEY" \
		|| fail "Cannot find the private key for roa1-1.roa"

	openssl dgst -sha256 -sign "$SIGNED_ATTRS_EE_KEY" \
		-out "$SIGNED_ATTRS_WORK/signature.bin" \
		"$SIGNED_ATTRS_WORK/to-sign.der" \
		> "$SIGNED_ATTRS_WORK/sign.log" 2>&1 \
		|| fail "Cannot sign mutated signedAttrs"
	test "$(wc -c < "$SIGNED_ATTRS_WORK/signature.bin")" -eq 256 \
		|| fail "The replacement CMS signature is not 256 bytes"

	perl - "$ROA" "$SIGNED_ATTRS_WORK/signature.bin" <<'PERL'
use strict;
use warnings;
my ($roa_path, $signature_path) = @ARGV;
sub read_all {
	my ($file) = @_;
	open my $input, '<:raw', $file or die "Cannot open $file: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}
my $roa = read_all($roa_path);
my $signature = read_all($signature_path);
die "ROA is too short for its signature\n" if length($roa) < length($signature);
substr($roa, -length($signature), length($signature)) = $signature;
open my $output, '>:raw', $roa_path or die "Cannot write $roa_path: $!\n";
print {$output} $roa;
close $output;
PERL
	test "$?" -eq 0 || fail "Cannot install the replacement CMS signature"

	openssl x509 -in "$CMS_WORK/ee.pem" -pubkey -noout \
		> "$SIGNED_ATTRS_WORK/ee-public.pem" 2>&1 \
		|| fail "Cannot extract the ROA EE public key"
	openssl dgst -sha256 -verify "$SIGNED_ATTRS_WORK/ee-public.pem" \
		-signature "$SIGNED_ATTRS_WORK/signature.bin" \
		"$SIGNED_ATTRS_WORK/to-sign.der" \
		> "$SIGNED_ATTRS_WORK/verify-signature.log" 2>&1 \
		|| fail "The replacement CMS signature is invalid"

	openssl cms -cmsout -inform DER -in "$ROA" -print \
		> "$SIGNED_ATTRS_WORK/cms-print.txt" 2>&1 \
		|| fail "The mutated roa1-1.roa is not valid DER CMS"
	openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
		-out "$SIGNED_ATTRS_WORK/content.der" \
		> "$SIGNED_ATTRS_WORK/extract-content.log" 2>&1 \
		|| fail "Cannot extract content from the mutated roa1-1.roa"
	cmp -s "$CMS_WORK/original-content.der" "$SIGNED_ATTRS_WORK/content.der" \
		|| fail "The signedAttrs mutation unexpectedly changed ROA eContent"

	publish_mutated_roa
}
