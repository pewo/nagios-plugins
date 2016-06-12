#! /usr/bin/perl -w
#
##########################################################################################
##########################################################################################
##########################################################################################
#
# check_stpblock.pl  -  Check if there are any stp blocking ports
# Written by Peter Wirdemo (peter <dot> wirdemo gmail <dot> com)
# 
# Latest version can be found at
# http://sites.google.com/site/peterwirdemo/home/nagios-plugins/check_stpblock.pl
#
#########
# Version
#########
#
# 0.1.2 2012-05-23
#
##############
# Description: 
##############
#
# This plugin will do a snmp scan on a switch and retrieve all spanningtree blocked ports.
# 
# If you specify --warning or --critical values, the plugin will exit if it finds more
# blocked ports. Default is 0 for both warning and critical.
# There is also an options to exclude ports from beeing counted, --exclude=1,2,9,50
# If you want there is a --performance option that print performance data, i.e
# the number of port and the number of blocked ports.
#
# Usage; check_stpblock.pl
#  
#  This nagios plugin is free software, and comes with ABSOLUTELY NO WARRANTY. 
#  It may be used, redistributed and/or modified under the terms of the GNU 
#  General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).
#  
#  Usage: 
#  
#   -?, --usage
#     Print usage information
#   -h, --help
#     Print detailed help screen
#   -V, --version
#     Print version information
#   --extra-opts=[section][@file]
#     Read options from an ini file. See http://nagiosplugins.org/extra-opts
#     for usage and examples.
#   -H, --hostname=<hostname>
#  
#   -C, --community=<community>
#  
#   -E, --exclude=<port,port,...port>
#  
#   -w, --warning=INTEGER
#     Report warning if there are <INTEGER> or more errorports
#  
#   -c, --critical=THRESHOLD
#     Report critical if there are <INTEGER> or more errorports
#  
#   -p --performance
#     Report performance data back to nagios
#   -t, --timeout=INTEGER
#     Seconds before plugin times out (default: 30)
#   -v, --verbose
#     Show details for command-line debugging (can repeat up to 3 times)
#  
#  
#  Copyright (c) 2012 peter.wirdemo@saabgroup.com
#  
##########################################################################################
##########################################################################################
##########################################################################################

use strict;
use warnings;
use vars qw($PROGNAME $VERSION $QSTRING);
use File::Basename qw(basename);
use Nagios::Plugin;
use Net::SNMP;
use Data::Dumper;

my($debug) = 0;
my($test) = "blocked";

$PROGNAME = basename($0);
$VERSION = '0.1.0';
$QSTRING = 'peter.wirdemo@gmail.com';

my $np = Nagios::Plugin->new(
  usage => "Usage: ",
  version => $VERSION,
  plugin  => $PROGNAME,
  shortname => uc($PROGNAME),
  blurb => 'Checks if there are any stp blocking ports',
  extra   => "\n\nCopyright (c) 2012 $QSTRING",
  timeout => 30,
);

$np->add_arg(
  spec => 'hostname|H=s',
  help => "-H, --hostname=<hostname>\n",
  required => 1,
);

$np->add_arg(
  spec => 'community|C=s',
  help => "-C, --community=<community>\n",
  required => 0,
);

$np->add_arg(
  spec => 'exclude|E=s',
  help => "-E, --exclude=<port,port,...port>\n",
  required => 0,
);

$np->add_arg(
  spec => 'warning|w=s',
  help => "-w, --warning=INTEGER\n"
    . "   Warning: Report warning if there are <INTEGER> or more blocked ports\n",
  required => 0,
);

$np->add_arg(
  spec => 'critical|c=s',
  help => "-c, --critical=INTEGER\n"
    . "   Critical: Report critical if there are <INTEGER> or more blocked ports \n",
  required => 0,
);

$np->add_arg(
  spec => 'performance|p',
  help => "-p --performance\n"
    . "   Report performance data back to nagios (no of ports and no of blocked ports)",
  required => 0,
);

$np->getopts;

# Assign, then check args

my $hostname = $np->opts->hostname;
print "hostname=[$hostname]\n" if ( $debug );
my $warning = $np->opts->warning || 0;
print "warning=[$warning]\n" if ( $debug );
my $critical = $np->opts->critical || 0;
print "critical=[$critical]\n" if ( $debug );
my $verbose = $np->opts->verbose;
print "verbose=[$verbose]\n" if ( $debug );
my $community = $np->opts->community || "public";
print "community=[$community]\n" if ( $debug );
my $exclude = $np->opts->exclude;
print "exclude=[$exclude]\n" if ( $debug && $exclude );
my(%exclude);
if ( $exclude ) {
	foreach ( split(/\D/,$exclude) ) {
		$exclude{$_}=1;
	}
	print Dumper(\%exclude) if ( $debug );
}
my $performance = $np->opts->performance || 0;
print "performance=[$performance]\n" if ( $debug );



$np->nagios_exit('UNKNOWN', 'Hostname contains invalid characters.')
  if ($hostname =~ /\`|\~|\!|\$|\%|\^|\&|\*|\||\'|\"|\<|\>|\?|\,|\(|\)|\=/);

# Just in case of problems, let's not hang Nagios
$SIG{ALRM} = sub {
    $np->nagios_exit(UNKNOWN, 'plugin timed out.');
};
alarm $np->opts->timeout;

#-- 1.3.6.1.2.1.17.2.15.1.3
#-- iso(1). org(3). dod(6). internet(1). mgmt(2). mib-2(1). 
#-- dot1dBridge(17). dot1dStp(2). dot1dStpPortTable(15). dot1dStpPortEntry(1). dot1dStpPortState(3)
my($base) = "1.3.6.1.2.1.17.2.15.1.3";

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
my($response);
my($errortot) = 0;
if ( ! defined ( $response = $session->get_table($base) ) ) {
	$np->nagios_exit(UNKNOWN, "plugin timed out: " . $session->error);
}

my($ports) = 0;

my(%id) = (
	disabled   => 1,   
	blocking   => 2,   
	listening  => 3,   
	learning   => 4,   
	forwarding => 5,   
	broken     => 6,
);

my(%stp);
my(%port);
while ( my($key,$value) = each %$response ) {
	$ports++;
	next unless ( $value );
	print "\tgot key=$key, value=$value\n" if ( $debug );
	my(@arr) = split(/\./,$key);
	my($port) = $arr[-1];
	print "port=[$port], value=[$value]\n" if ( $debug );
	if ( $exclude{$port} ) {
		print "Excluding $port\n" if ( $verbose );
	}
	else {
		$stp{$value}++;
		$port{$value} .= "$port ";
	}
}

print Dumper(\%port) if ( $debug );

$session->close;

my($errorstr) = "";
my($perfstr) = "";

my($errports) = 0;
my($detail) = "";
my($id);
if ( $performance ) {
	$np->add_perfdata(
		label => "Ports",
		value => $ports,
	);
}

if ( $test eq "blocked" ) {
	$id = $id{blocking};
	$errports = $stp{$id} || 0;
	if ( $port{$id} ) {
		$detail = join(" ",( sort { $a <=> $b } split(/\s+/,$port{$id}) ));
	}
	if ( $performance ) {
		$np->add_perfdata(
            	label => "Blocked",
            	value => $errports,
		);
	}
}

if ( $critical ) {
	if ( $errports >= $critical ) {
		$np->nagios_exit( CRITICAL, "$test ports: $detail" );
	}
}
if ( $warning ) {
	if ( $errports >= $warning ) {
		$np->nagios_exit( WARNING, "$test ports: $detail" );
	}
}

$np->nagios_exit( OK, "Ports: $ports, $test: $errports" );
