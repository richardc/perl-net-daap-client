use Test::More qw(no_plan);
use Data::Dumper;

BEGIN { use_ok('Net::DAAP::DMAP') };

use Net::DAAP::DMAP qw(:all);

sub slurp {
  my ($fname) = @_;
  open my $fh, "<", $fname or die "Can't open $fname: $!";
  local $/;
  return <$fh>;
}

$flattened_output = slurp("t/login.flattened");
$xml_output = slurp("t/login.xml");
$unpack_output = slurp("t/login.unpacked");
$dmap = slurp("t/login.response");

$unpacked = dmap_unpack($dmap);

is($unpack_output, Dumper($unpacked), "unpack");
is($xml_output, dmap_to_xml($dmap), "xml");
is($flattened_output, Dumper(dmap_flatten($unpacked)), "flatten");

