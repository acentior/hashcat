#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 256], [40, 40], [0, 55], [40, 40], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $hash_buf = sha1_hex ($salt . sha1_hex ($salt . sha1_hex ($word)));

  my $hash = sprintf ("%s:%s", $hash_buf, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
