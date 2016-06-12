#!/usr/bin/perl -w
#
# check_dot3.pl  -  Check dot3 interface statistcs
#

use strict;
use warnings;
use vars qw($PROGNAME $VERSION $QSTRING);
use File::Basename qw(basename);
use Nagios::Plugin;
use Net::SNMP;
use Data::Dumper;

$PROGNAME = basename($0);
$VERSION = '0.1.2';
$QSTRING = 'peter.wirdemo@gmail.com';

my $savedir = "/var/tmp/check_dot3";
my $community = "public";

my $np = Nagios::Plugin->new(
  usage => "Usage: %s -H <hostname> ...\n",
  version => $VERSION,
  plugin  => $PROGNAME,
  shortname => "check_dot3",
  blurb => "Get all data from dot3StatsTable in the Etherlike MIB from the host.\n"
	. "Add all values from all interfaces and calculate the sum of all errors.\n" 
	. "If the sum/second (i.e since last run) is larger then warning or critical\n"
	. "appropriate exit values are returned to nagios."
	,
  extra   => "\n\nCopyright (c) 2010 Peter Wirdemo, firname.lastname\@gmail.com",
  timeout => 30,
);

$np->add_arg(
  spec => 'hostname|H=s',
  help => "-H, --hostname=<hostname>",
  required => 1,
);

$np->add_arg(
  spec => 'community|C=s',
  help => "-C, --community=<snmp read community> (default is $community)",
  required => 0,
);

$np->add_arg(
  spec => 'warning|w=s',
  help => "-w --warning\n"
	. "   report warn if more failures/sec are found",
  required => 0,
);

$np->add_arg(
  spec => 'critical|c=s',
  help => "-c --critical\n"
	. "   report critical if more failures/sec are found",
  required => 0,
);

$np->add_arg(
  spec => 'performance|p',
  help => "-p --performance\n"
	. "   Report performance data back to nagios",
  required => 0,
);

$np->add_arg(
  spec => 'savedir|s=s',
  help => "-s --savedir=<directory>\n"
    . "   Directory to save stats between runs, default is $savedir\n"
    . "   If the directory does not exists, it will be created",
  required => 0,
);

$np->getopts;

# Assign, then check args

my $verbose = $np->opts->verbose;
$community = $np->opts->community if ( $np->opts->community );
print "community=$community\n" if ( $verbose );
my $hostname = $np->opts->hostname;
print "hostname=$hostname\n" if ( $verbose );
my $warning;
$warning = $np->opts->warning if ( $np->opts->warning );
my $critical;
$critical = $np->opts->critical if ( $np->opts->critical );

$savedir = $np->opts->savedir if ( $np->opts->savedir );
my $performance = 0;
$performance = $np->opts->performance if ( $np->opts->performance );

$np->nagios_exit('UNKNOWN', 'Hostname contains invalid characters.')
  if ($hostname =~ /\`|\~|\!|\$|\%|\^|\&|\*|\||\'|\"|\<|\>|\?|\,|\(|\)|\=/);

if ( ! -d $savedir ) {
	print "Creating directory: $savedir\n" if ( $verbose );
	mkdir($savedir);
	my($mode);
	$mode = 0755;   
	chmod $mode, $savedir;
}
if ( ! -d $savedir ) {
	chdir($savedir);
	$np->nagios_exit(UNKNOWN, $!);
}

# Just in case of problems, let's not hang Nagios
$SIG{ALRM} = sub {
    $np->nagios_exit(UNKNOWN, 'plugin timed out.');
};
alarm $np->opts->timeout;

my($base) = "1.3.6.1.2.1.10.7.2.1";

my $perf_oids = {
	dot3StatsAlignmentErrors            => {
		snmpoid =>  $base . ".2",
		legend => "Alignment",
	},
	dot3StatsFCSErrors                  => {
		snmpoid =>  $base . ".3",
		legend => "FCS",
	},
	dot3StatsSingleCollisionFrames      => {
		snmpoid =>  $base . ".4",
		legend => "SinCol",
	},
	dot3StatsMultipleCollisionFrames    => {
		snmpoid =>  $base . ".5",
		legend => "MulCol",
	},
	dot3StatsSQETestErrors              => {
		snmpoid =>  $base . ".6",
		legend => "SQE",
	},
	dot3StatsDeferredTransmissions      => {
		snmpoid =>  $base . ".7",
		legend => "DefTra",
	},
	dot3StatsLateCollisions             => {
		snmpoid =>  $base . ".8",
		legend => "LatCol",
	},
	dot3StatsExcessiveCollisions        => {
		snmpoid =>  $base . ".9",
		legend => "ExcCol",
	},
	dot3StatsInternalMacTransmitErrors  => {
		snmpoid =>  $base . ".10",
		legend => "MacTra",
	},
	dot3StatsCarrierSenseErrors         => {
		snmpoid =>  $base . ".11",
		legend => "CarSen",
	},
	dot3StatsFrameTooLongs              => {
		snmpoid =>  $base . ".13",
		legend => "FraLong",
	},
	dot3StatsInternalMacReceiveErrors   => {
		snmpoid =>  $base . ".16",
		legend => "MacRec",
	},
	dot3StatsSymbolErrors               => {
		snmpoid =>  $base . ".18",
		legend => "SymErr",
	},
};



my($snmp_version) = 2;
my($port) = 161;

my($session);
my($error);
if ( $snmp_version =~ /[12]/ ) {
	print "Creating snmp session\n" if ( $verbose );
	($session,$error) = Net::SNMP->session(
			-hostname => $hostname,
			-community => $community,
			-port => $port,
			-version => $snmp_version,
			);
	if ( ! defined $session ) {
		$np->nagios_exit('UNKNOWN',$error);
	}
}

my($key);

my(%absperf);
my($tot) = 0;
my($legend); 

my($data_avail) = 0;
foreach $key ( sort keys %$perf_oids ) {
	print "Key=$key\n" if ( $verbose );

	my($average) = $perf_oids->{$key}{average};
	my($snmpoid)= $perf_oids->{$key}{snmpoid};

	my(@oids);
	if ( ref($snmpoid) eq "ARRAY" ) {
		foreach ( @$snmpoid ) {
			push(@oids,$_);
		}
	}
	elsif ( ref($snmpoid) eq "HASH" ) {
		foreach ( values %$snmpoid ) {
			push(@oids,$_);
		}
	}
	else {
		push(@oids,$snmpoid);
	}

	$legend = $key;
	$legend= $perf_oids->{$key}{legend} if ( $perf_oids->{$key}{legend} );
	print "\tlegend=$legend\n" if ( $verbose );

# do the query
	my($response);
	my($answer);
	my($sum) = 0;
	my($cnt) = 0;
	my($oid);
	my($ok) = 0;
	foreach $oid ( @oids ) {
		print "\tquery: $oid\n" if ( $verbose );
		if ( ! defined ( $response = $session->get_table($oid) ) ) {
			next;
		}

		$data_avail++;

		while ( my($key,$value) = each %$response ) {
			print "\tgot key=$key, value=$value\n" if ( $verbose );
			$cnt++;
			$sum += $value;
			$tot += $value;
		}
	}
	my($res) = $sum;
	if ( $cnt > 1 && $average ) {
		$res = int($sum/$cnt);
	}

	$absperf{$legend}=$res;
}

my(%procperf);
foreach $legend ( keys %absperf ) {
	my($val) = $absperf{$legend};
	my($proc) = 0;
	if ( $val > 0 ) {
		$proc = sprintf("%4.1f",100 * ($val/$tot));
		$proc =~ s/^\s+//;
	}
	$procperf{$legend}= "$proc%;;;0;100";
}

my($perfstr) = "";
foreach $legend ( sort keys %procperf ) {
	$perfstr .= $legend . "=" . $procperf{$legend} . " ";
}

$session->close;

my($db) = $savedir . "/" . $hostname . ".db";
my($prev_cnt) = 0;
my($prev_time) = 0;
if ( open(IN,"<$db") ) {
	print "Reading database $db\n" if ( $verbose );
	my($line);
	($prev_time,$prev_cnt) = split(/:/,<IN>);
	print "read prev_time=$prev_time (" . localtime($prev_time) . ")\n" if ( $verbose );
	print "read prev_cnt=$prev_cnt\n" if ( $verbose );
	close(IN);
}

my($curr_cnt) = $tot;
my($curr_time) = time;

if ( open(OUT,">$db") ) {
	print "Writing database $db\n" if ( $verbose );
	#print OUT $curr_time . ":" . $curr_cnt;
	print OUT $curr_time . ":0";
	print "wrote curr_time=$curr_time (" . localtime($curr_time) . ")\n" if ( $verbose );
	print "read curr_cnt=$curr_cnt\n" if ( $verbose );
	close(OUT);
}
#Turn off alarm
alarm(0);

my($errorstr) = "Dot3Errors: $curr_cnt";
unless ( $data_avail ) {
	$errorstr .=  " (*No data/SNMP Error*)";
}
my($errors) = 0;
my($persec) = 0;
my($diff_cnt) = 0;
my($diff_time) = 0;
my($diff_min_sec) = 0;
if ( $prev_time ) {
	$diff_time = $curr_time - $prev_time;
	my($minutes) = int($diff_time/60);
	$diff_min_sec = sprintf("%dm%ds",$minutes,$diff_time - $minutes*60);
	$diff_cnt = $curr_cnt - $prev_cnt;
	if ( $diff_cnt < 0 ) {
		$diff_cnt = $curr_cnt;
	}
	if ( $diff_time > 0 ) {
		$persec = int($diff_cnt/$diff_time);
	}
}

$perfstr = "AllDot3Err=$curr_cnt AllPerSec=$persec $perfstr";
$errorstr .= ", Diff=$diff_cnt/$diff_min_sec ($persec/s) ";
my($rc) = 'OK';
unless ( $data_avail ) {
	$rc  = 'UNKNOWN';
}
if ( $persec > 0 ) {
	print "Current error level per seconds is $persec\n" if ( $verbose );
	if ( defined($warning) ) {
		print "warning level is at $warning\n" if ( $verbose );
		if ( $persec > $warning ) {
			$rc = 'WARNING';
		}
	}
	if ( defined($critical) ) {
		print "critical level is at $critical\n" if ( $verbose );
		if ( $persec > $critical ) {
			$rc = 'CRITICAL';
		}
	}
}

if ( $performance ) {
	$errorstr .= "|" . $perfstr;
}
$np->nagios_exit($rc,$errorstr);
