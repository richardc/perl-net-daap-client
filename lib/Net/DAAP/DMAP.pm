package Net::DAAP::DMAP;
use strict;

=pod

=head1 NAME

Net::DAAP::DMAP - Perl module for reading and writing DAAP structures

=head2 SYNOPSIS

  use Net::DAAP::DMAP qw(:all);

  $hash_ref = dmap_to_hash_ref($dmap);       # crude
  $array_ref = dmap_to_array_ref($dmap);     # crude

  $array_ref = dmap_unpack($dmap);           # knows about data types
  $node      = dmap_seek($array_ref, $path);

  $flattened = dmap_flatten($array_ref);     # convert to path = data format
  $xml       = dmap_to_xml($dmap);           # convert to XML fragment
  $dmap      = dmap_pack($dmap);             # convert to DMAP packet
  update_content_codes($unpacked_content_codes_response);

=head1 DESCRIPTION

=head2 WARNING!

Until 1.0, I reserve the right to change the interface.  In
particular, I think C<dmap_flatten>, C<dmap_to_hash_ref>, and
C<dmap_to_array_ref> are likely
to disappear.  And I suspect the hive brain of Perl can come up with a
better data structure than I have.

=head2 Back to the Description

A DMAP structure is a binary record used in Apple's DAAP protocol.  A
DMAP structure may contain other DMAP structures.  Fields in a DMAP
structure are identified by a short name ("msdc").  The short name is
what's in the binary record, but a content codes list gives a long
name ("dmap.databasescount") and a data type for the record (32-bit
integer).

A parsed DMAP structure is built out of arrays.  For example:

  [
    [
      'dmap.loginresponse',
      [
         [
           'dmap.status',
           200
         ],
         [
           'dmap.sessionid',
            2393
         ]
      ]
    ]
  ]

(C<dmap_unpack> returns this kind of structure)

There are two rules here: a field is wrapped in an array, and
a container's values are wrapped in an array.  So the structure
is programmatically built as:

  $status_field = [ 'dmap.status', 200 ];
  $session_id_field = [ 'dmap.sessionid', 2393 ];
  $response_value = [ $status_field, $session_id_field ];
  $login_response_field = [ 'dmap.loginresponse', $response_value ];
  $entire_response = [ $login_response_field ];

The outer array is necessary because not every response has only one
top-level container as this does.

In XML you'd write the response as:

  <dmap.loginresponse>
      <dmap.status>200</dmap.status>
      <dmap.sessionid>2393</dmap.sessionid>
  </dmap.loginresponse>

This is what C<dmap_to_xml> returns.

A much more convenient structure for representing this data would
be:

  {
    'dmap.loginresponse' => {
      { 'dmap.status' => 200,
        'dmap.sessionid' => 2393,
      },
  }

This is the output of C<dmap_to_hash_ref>, but beware!  This isn't
suitable for every response.  The hash is indexed by field name and a
structure may contain many elements of the same name.  For example,
requesting the content codes list gives you a list of records that
have the field name C<dmap.dictionary>.

The array structure returned by C<dmap_to_array_ref> is complex, but
the C<dmap_seek> function makes it easier.  This takes a structure and
a path expressed as a slash-separated list of field names:

  dmap.loginresponse/dmap.sessionid

The return value is the the value of the first C<dmap.sessionid> found
in the first C<dmap.loginresponse> structure.  In the case of the
sample record above, it would be 2393.

Another way to handle these complex arrays is to C<dmap_flatten> them.
This returns an array of "I<path> = value" lines, where I<path> is
a slash-separated path.  For example:

  [
    '/dmap.loginresponse/dmap.status = 200',
    '/dmap.loginresponse/dmap.sessionid = 2393'
  ]

You can use C<grep> and regexps to find data if that's the way your
mind works.

You can, but don't have to, update the tables of field names ("content
codes") and data types.  DAAP offers a request that returns a packet
of content codes.  Feed that packet to C<update_content_codes>.

=head2 Implementation Details

It's all implementation details.  Here are the various data types.

 1, 3, 5, 7 = ints, size 8,16,32,64 bit
 9 = string, 10 = time_t-style time
 11 = version (two 16-bit ints, I think)
 12 = container

This uses Math::BigInt for 64-bit quantities, as not every platform
has 64-bit int support available.

There's no support for types 2, 4, 6, 8 yet because nobody'd found
examples of them in the field: are they endian changes, or signedness
changes.  The assumption is that all numbers are unsigned (why allow
the possibility of a negative number of songs?).

=head1 AUTHOR

Nathan Torkington, <nathan AT torkington.com>.  For support, join the
DAAP developers mailing list by sending mail to <daap-devel-subscribe
AT develooper.com>.

=cut

use Exporter;
use Math::BigInt;
use Carp;

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(dmap_to_hash_ref dmap_to_array_ref update_content_codes
                    dmap_unpack dmap_to_xml dmap_seek dmap_flatten dmap_pack );
our %EXPORT_TAGS = ( 'all' => \@EXPORT_OK );

our $Types;
my %Type_To_Unpack;
my $Container_Type;

# initialize the types and their unpack() equivalents
init();

sub init {
    local $/;
    $Types = eval <DATA>;

    $Container_Type = 12;

    %Type_To_Unpack = (
                       1 => 'c',
                       3 => 'n',
                       5 => 'N',
                       7 => 'Q',
                       9, 'a*',
                       10 => 'N',
                       11 => 'nn',
                       );
}

sub dmap_to_hash_ref {
    my $buf = shift;
    my %tags;

    while (length $buf) {
        my ($tag, $len) = unpack("a4N", $buf);
        if (!defined($len) or length $buf < 8+$len) {
            return;
          }
        my $data = substr($buf, 8, $len);
        # try to unpack--if we can, assume it was a container
        my $data2 = dmap_to_hash_ref($data);
        $tags{$tag} = $data2 ? $data2 : $data;
        substr($buf, 0, 8+$len) = '';
      }
    return \%tags;
}

sub dmap_flatten {
    my $struct = shift;
    my $arrayref = [];

    flatten_traverse($arrayref, "", $struct);
    return $arrayref;
}

sub flatten_traverse {
    my ($array_ref, $prefix, $struct) = @_;

    foreach my $ref (@$struct) {
        for (my $i=0; $i < @$ref; $i+=2) {
            my ($tag, $data) = ($ref->[$i], $ref->[$i+1]);

            if (ref $data eq 'ARRAY') {
                flatten_traverse($array_ref, "$prefix/$tag", $data);
            } else {
                push @$array_ref, "$prefix/$tag = $data";
            }
        }
    }
}


sub dmap_unpack {
    my $buf = shift;
    my @tags;

    while (length $buf) {
        my ($tag, $len) = unpack("a4N", $buf);
        my $data = substr($buf, 8, $len);
        my $type = $Types->{$tag}{TYPE};

        if ($type == 12) {
            $data = dmap_unpack($data);
        } elsif ($type == 7) {
            my ($n1, $n2) = unpack("N2", $data);
            $data = new Math::BigInt(new Math::BigInt($n1)->blsft(32));
            $data += $n2;
            $data = "$data";
        } else {
            $data = unpack($Type_To_Unpack{$type}, $data);
        }
        push @tags, [ $Types->{$tag}{NAME}, $data ];
        substr($buf, 0, 8+$len) = '';
    }

    return \@tags;
}

sub dmap_to_xml {
    my $buf = shift;
    my $xml = '';

    while (length $buf) {
        my ($tag, $len) = unpack("a4N", $buf);
        my $data = substr($buf, 8, $len);
        my $type = $Types->{$tag}{TYPE};

        if ($type == 12) {
            $data = dmap_to_xml($data);
        } else {
            $data = unpack($Type_To_Unpack{$type}, $data);
        }
        $xml .= sprintf("<%s>\n  %s\n</%s>\n", $tag, $data, $tag);
        substr($buf, 0, 8+$len) = '';
      }
    return $xml;
}

sub dmap_to_array_ref {
    my $buf = shift;
    my @tags;

    while (length $buf) {
        my ($tag, $len) = unpack("a4N", $buf);
        if (!defined($len) or length $buf < 8+$len) {
            return;
          }
        my $data = substr($buf, 8, $len);
        # try to unpack, assume it was a container if it succeeded
        my $data2 = dmap_to_array_ref($data);
        push @tags, [ $tag,  $data2 ? $data2 : $data ];
        substr($buf, 0, 8+$len) = '';
      }
    return \@tags;
}

sub dmap_seek {
    my($struct, $to_find) = @_;

    CHUNK: while (defined($to_find) && length($to_find)) {
        my $top;
        ($top, $to_find) = split m{/}, $to_find, 2;

      ELEMENT: foreach my $elt (@$struct) {

          if ($elt->[0] eq $top) {
                $struct = $elt->[1];
                next CHUNK;
            }
        }
        return;  # NOT FOUND
    }
    return $struct;
}

my %by_name;
sub update_content_codes {
  my $array = shift;
  my $short;

  my $mccr = dmap_seek($array, "dmap.contentcodesresponse");
  die "Couldn't find mccr" unless defined $mccr;

  foreach my $mdcl_rec (@$mccr) {
    next unless $mdcl_rec->[0] eq 'dmap.dictionary';
    my @fields = @{$mdcl_rec->[1]};
    my ($name, $id, $type);
    foreach my $f (@fields) {
      if ($f->[0] eq 'dmap.contentcodesnumber') { $id = $f->[1] }
      if ($f->[0] eq 'dmap.contentcodesname') { $name = $f->[1] }
      if ($f->[0] eq 'dmap.contentcodestype') { $type = $f->[1] }
    }
    if ($name eq 'mcnm') { $type = 9 } # string names please
    my $record = { NAME => $name, ID => $id, TYPE => $type };
    $short->{$id} = $record;
  }

  $Types = $short;
  %by_name = map { $_->{NAME} => $_ } values %$Types;
}

%by_name = map { $_->{NAME} => $_ } values %$Types;
sub dmap_pack {
    my $struct = shift;
    my $out = '';

    for my $pair (@$struct) {
        my ($name, $value) = @$pair;
        # dmap_unpack doesn't populate the name when its decoded
        # something it doesn't know the content-code of, like aeSV
        # which is new to 4.5
        unless ($name) {
            carp "element without a name - skipping";
            next;
        }
        # or, it may be we don't know what kind of thing this is
        unless (exists $by_name{ $name }) {
            carp "we don't know the type for '$name' elements - skipping";
            next;
        }

        my $tag  = $by_name{ $name }{ID};
        my $type = $by_name{ $name }{TYPE};
        #print "$name => $tag $type $Type_To_Unpack{$type}\n";
        #$SIG{__WARN__} = sub { die @_ };
        if ($type == 12) { # container
            $value = dmap_pack( $value );
        }
        elsif ($type == 7) { # 64-bit
            my $high = Math::BigInt->new( $value )->brsft(32)."";
            my $low  = Math::BigInt->new( $value )->band(0xFFFFFFFF)."";
            $value = pack( "N2", $high, $low );
        }
        else {
            no warnings 'uninitialized';
            $value = pack( $Type_To_Unpack{$type}, $value );
        }
        my $length = do { use bytes; length $value };
        $out .= $tag . pack("N", $length) . $value;
    }
    return $out;
}



1;

__DATA__
{
          'mper' => {
                      'ID' => 'mper',
                      'NAME' => 'dmap.persistentid',
                      'TYPE' => 7
                    },
          'arif' => {
                      'ID' => 'arif',
                      'NAME' => 'daap.resolveinfo',
                      'TYPE' => 12
                    },
          'mcon' => {
                      'ID' => 'mcon',
                      'NAME' => 'dmap.container',
                      'TYPE' => 12
                    },
          'mbcl' => {
                      'ID' => 'mbcl',
                      'NAME' => 'dmap.bag',
                      'TYPE' => 12
                    },
          'mcnm' => {
                      'ID' => 'mcnm',
                      'NAME' => 'dmap.contentcodesnumber',
                      'TYPE' => 9
                    },
          'mudl' => {
                      'ID' => 'mudl',
                      'NAME' => 'dmap.deletedidlisting',
                      'TYPE' => 12
                    },
          'asda' => {
                      'ID' => 'asda',
                      'NAME' => 'daap.songdateadded',
                      'TYPE' => 10
                    },
          'asyr' => {
                      'ID' => 'asyr',
                      'NAME' => 'daap.songyear',
                      'TYPE' => 3
                    },
          'mlid' => {
                      'ID' => 'mlid',
                      'NAME' => 'dmap.sessionid',
                      'TYPE' => 5
                    },
          'msex' => {
                      'ID' => 'msex',
                      'NAME' => 'dmap.supportsextensions',
                      'TYPE' => 1
                    },
          'assr' => {
                      'ID' => 'assr',
                      'NAME' => 'daap.songsamplerate',
                      'TYPE' => 5
                    },
          'asdb' => {
                      'ID' => 'asdb',
                      'NAME' => 'daap.songdisabled',
                      'TYPE' => 1
                    },
          'mlit' => {
                      'ID' => 'mlit',
                      'NAME' => 'dmap.listingitem',
                      'TYPE' => 12
                    },
          'asco' => {
                      'ID' => 'asco',
                      'NAME' => 'daap.songcompilation',
                      'TYPE' => 1
                    },
          'asdm' => {
                      'ID' => 'asdm',
                      'NAME' => 'daap.songdatemodified',
                      'TYPE' => 10
                    },
          'aeNV' => {
                      'ID' => 'aeNV',
                      'NAME' => 'com.apple.itunes.norm-volume',
                      'TYPE' => 5
                    },
          'mccr' => {
                      'ID' => 'mccr',
                      'NAME' => 'dmap.contentcodesresponse',
                      'TYPE' => 12
                    },
          'msts' => {
                      'ID' => 'msts',
                      'NAME' => 'dmap.statusstring',
                      'TYPE' => 9
                    },
          'ascp' => {
                      'ID' => 'ascp',
                      'NAME' => 'daap.songcomposer',
                      'TYPE' => 9
                    },
          'aseq' => {
                      'ID' => 'aseq',
                      'NAME' => 'daap.songeqpreset',
                      'TYPE' => 9
                    },
          'mstt' => {
                      'ID' => 'mstt',
                      'NAME' => 'dmap.status',
                      'TYPE' => 5
                    },
          'msal' => {
                      'ID' => 'msal',
                      'NAME' => 'dmap.supportsautologout',
                      'TYPE' => 1
                    },
          'muty' => {
                      'ID' => 'muty',
                      'NAME' => 'dmap.updatetype',
                      'TYPE' => 1
                    },
          'asfm' => {
                      'ID' => 'asfm',
                      'NAME' => 'daap.songformat',
                      'TYPE' => 9
                    },
          'abgn' => {
                      'ID' => 'abgn',
                      'NAME' => 'daap.browsegenrelisting',
                      'TYPE' => 12
                    },
          'mupd' => {
                      'ID' => 'mupd',
                      'NAME' => 'dmap.updateresponse',
                      'TYPE' => 12
                    },
          'asal' => {
                      'ID' => 'asal',
                      'NAME' => 'daap.songalbum',
                      'TYPE' => 9
                    },
          'abro' => {
                      'ID' => 'abro',
                      'NAME' => 'daap.databasebrowse',
                      'TYPE' => 12
                    },
          'miid' => {
                      'ID' => 'miid',
                      'NAME' => 'dmap.itemid',
                      'TYPE' => 5
                    },
          'ascm' => {
                      'ID' => 'ascm',
                      'NAME' => 'daap.songcomment',
                      'TYPE' => 9
                    },
          'mspi' => {
                      'ID' => 'mspi',
                      'NAME' => 'dmap.supportspersistentids',
                      'TYPE' => 1
                    },
          'musr' => {
                      'ID' => 'musr',
                      'NAME' => 'dmap.serverrevision',
                      'TYPE' => 5
                    },
          'assz' => {
                      'ID' => 'assz',
                      'NAME' => 'daap.songsize',
                      'TYPE' => 5
                    },
          'msau' => {
                      'ID' => 'msau',
                      'NAME' => 'dmap.authenticationmethod',
                      'TYPE' => 1
                    },
          'astm' => {
                      'ID' => 'astm',
                      'NAME' => 'daap.songtime',
                      'TYPE' => 5
                    },
          'asdn' => {
                      'ID' => 'asdn',
                      'NAME' => 'daap.songdiscnumber',
                      'TYPE' => 3
                    },
          'astn' => {
                      'ID' => 'astn',
                      'NAME' => 'daap.songtracknumber',
                      'TYPE' => 3
                    },
          'assp' => {
                      'ID' => 'assp',
                      'NAME' => 'daap.songstoptime',
                      'TYPE' => 5
                    },
          'aeSP' => {
                      'ID' => 'aeSP',
                      'NAME' => 'com.apple.itunes.smart-playlist',
                      'TYPE' => 1
                    },
          'asgn' => {
                      'ID' => 'asgn',
                      'NAME' => 'daap.songgenre',
                      'TYPE' => 9
                    },
          'mpco' => {
                      'ID' => 'mpco',
                      'NAME' => 'dmap.parentcontainerid',
                      'TYPE' => 5
                    },
          'msrs' => {
                      'ID' => 'msrs',
                      'NAME' => 'dmap.supportsresolve',
                      'TYPE' => 1
                    },
          'avdb' => {
                      'ID' => 'avdb',
                      'NAME' => 'daap.serverdatabases',
                      'TYPE' => 12
                    },
          'msrv' => {
                      'ID' => 'msrv',
                      'NAME' => 'dmap.serverinforesponse',
                      'TYPE' => 12
                    },
          'mslr' => {
                      'ID' => 'mslr',
                      'NAME' => 'dmap.loginrequired',
                      'TYPE' => 1
                    },
          'msup' => {
                      'ID' => 'msup',
                      'NAME' => 'dmap.supportsupdate',
                      'TYPE' => 1
                    },
          'mimc' => {
                      'ID' => 'mimc',
                      'NAME' => 'dmap.itemcount',
                      'TYPE' => 5
                    },
          'mcna' => {
                      'ID' => 'mcna',
                      'NAME' => 'dmap.contentcodesname',
                      'TYPE' => 9
                    },
          'apro' => {
                      'ID' => 'apro',
                      'NAME' => 'daap.protocolversion',
                      'TYPE' => 11
                    },
          'abar' => {
                      'ID' => 'abar',
                      'NAME' => 'daap.browseartistlisting',
                      'TYPE' => 12
                    },
          'mdcl' => {
                      'ID' => 'mdcl',
                      'NAME' => 'dmap.dictionary',
                      'TYPE' => 12
                    },
          'adbs' => {
                      'ID' => 'adbs',
                      'NAME' => 'daap.databasesongs',
                      'TYPE' => 12
                    },
          'aply' => {
                      'ID' => 'aply',
                      'NAME' => 'daap.databaseplaylists',
                      'TYPE' => 12
                    },
          'mstm' => {
                      'ID' => 'mstm',
                      'NAME' => 'dmap.timeoutinterval',
                      'TYPE' => 5
                    },
          'asbt' => {
                      'ID' => 'asbt',
                      'NAME' => 'daap.songbeatsperminute',
                      'TYPE' => 3
                    },
          'asrv' => {
                      'ID' => 'asrv',
                      'NAME' => 'daap.songrelativevolume',
                      'TYPE' => 1
                    },
          'mcti' => {
                      'ID' => 'mcti',
                      'NAME' => 'dmap.containeritemid',
                      'TYPE' => 5
                    },
          'asdk' => {
                      'ID' => 'asdk',
                      'NAME' => 'daap.songdatakind',
                      'TYPE' => 1
                    },
          'mlog' => {
                      'ID' => 'mlog',
                      'NAME' => 'dmap.loginresponse',
                      'TYPE' => 12
                    },
          'asbr' => {
                      'ID' => 'asbr',
                      'NAME' => 'daap.songbitrate',
                      'TYPE' => 3
                    },
          'msix' => {
                      'ID' => 'msix',
                      'NAME' => 'dmap.supportsindex',
                      'TYPE' => 1
                    },
          'mcty' => {
                      'ID' => 'mcty',
                      'NAME' => 'dmap.contentcodestype',
                      'TYPE' => 3
                    },
          'arsv' => {
                      'ID' => 'arsv',
                      'NAME' => 'daap.resolve',
                      'TYPE' => 12
                    },
          'msqy' => {
                      'ID' => 'msqy',
                      'NAME' => 'dmap.supportsquery',
                      'TYPE' => 1
                    },
          'abal' => {
                      'ID' => 'abal',
                      'NAME' => 'daap.browsealbumlisting',
                      'TYPE' => 12
                    },
          'mikd' => {
                      'ID' => 'mikd',
                      'NAME' => 'dmap.itemkind',
                      'TYPE' => 1
                    },
          'astc' => {
                      'ID' => 'astc',
                      'NAME' => 'daap.songtrackcount',
                      'TYPE' => 3
                    },
          'minm' => {
                      'ID' => 'minm',
                      'NAME' => 'dmap.itemname',
                      'TYPE' => 9
                    },
          'mctc' => {
                      'ID' => 'mctc',
                      'NAME' => 'dmap.containercount',
                      'TYPE' => 5
                    },
          'mrco' => {
                      'ID' => 'mrco',
                      'NAME' => 'dmap.returnedcount',
                      'TYPE' => 5
                    },
          'mtco' => {
                      'ID' => 'mtco',
                      'NAME' => 'dmap.specifiedtotalcount',
                      'TYPE' => 5
                    },
          'abpl' => {
                      'ID' => 'abpl',
                      'NAME' => 'daap.baseplaylist',
                      'TYPE' => 1
                    },
          'asur' => {
                      'ID' => 'asur',
                      'NAME' => 'daap.songuserrating',
                      'TYPE' => 1
                    },
          'asst' => {
                      'ID' => 'asst',
                      'NAME' => 'daap.songstarttime',
                      'TYPE' => 5
                    },
          'abcp' => {
                      'ID' => 'abcp',
                      'NAME' => 'daap.browsecomposerlisting',
                      'TYPE' => 12
                    },
          'apso' => {
                      'ID' => 'apso',
                      'NAME' => 'daap.playlistsongs',
                      'TYPE' => 12
                    },
          'asdt' => {
                      'ID' => 'asdt',
                      'NAME' => 'daap.songdescription',
                      'TYPE' => 9
                    },
          'mpro' => {
                      'ID' => 'mpro',
                      'NAME' => 'dmap.protocolversion',
                      'TYPE' => 11
                    },
          'msbr' => {
                      'ID' => 'msbr',
                      'NAME' => 'dmap.supportsbrowse',
                      'TYPE' => 1
                    },
          'mlcl' => {
                      'ID' => 'mlcl',
                      'NAME' => 'dmap.listing',
                      'TYPE' => 12
                    },
          'asdc' => {
                      'ID' => 'asdc',
                      'NAME' => 'daap.songdisccount',
                      'TYPE' => 3
                    },
          'asar' => {
                      'ID' => 'asar',
                      'NAME' => 'daap.songartist',
                      'TYPE' => 9
                    },
          'asul' => {
                      'ID' => 'asul',
                      'NAME' => 'daap.songdataurl',
                      'TYPE' => 9
                    },
          'msdc' => {
                      'ID' => 'msdc',
                      'NAME' => 'dmap.databasescount',
                      'TYPE' => 5
                    }
        };
