#! /usr/bin/perl -w
#
# check_entPhySensor.pl  -  Check (and graph) a procurve version
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

	

sub trimhash {
	my($orghash) = shift;

	my($key);
	my(%res);
	foreach $key ( keys %$orghash ) {
		my($value) = $orghash->{$key};
		$key =~ s/(.*\.)(\d+)$/$2/;
		$res{$key} = $value;
	}

	return(%res);
}


my $np = Nagios::Plugin->new(
  usage => "Usage: %s -H <hostname> -C <community>  -s check_entPhySensorId [ -p ] [ -l ] [ -w|--warning=<warning threshold> ] [ -c|--critical=<critical threshold>]\n",
  version => $VERSION,
  plugin  => $PROGNAME,
  shortname => "check_entPhySensor",
  blurb => 'Check an entry in the entitySensorMIB',
  extra   => "\n\nCopyright (c) 2010 Peter Wirdemo (firstname.lastname\@gmail.com)",
  timeout => 30,
);

$np->add_arg(
  spec => 'hostname|H=s',
  help => "-H, --hostname=<hostname>",
  required => 1,
);

$np->add_arg(
  spec => 'sensor|s=i',
  help => "-s --sensor=<sensor>\n"
    . "   Sensorid to check, use the -l to list available sensors on your system",
  required => 0,
);

$np->add_arg(
  spec => 'list|l',
  help => "-l, --list\n"
    . "   List available sensors on your system, the sensor value is used with --sensor option",
  required => 0,
);

$np->add_arg(
  spec => 'community|C=s',
  help => "-C, --community=<snmp read community>",
  required => 0,
);

$np->add_arg(
  spec => 'warning|w=s',
  help => "-w, --warning=INTEGER:INTEGER\n"
	. "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT\n"
	. "   for the threshold format.",
  required => 0,
);

$np->add_arg(
  spec => 'critical|c=s',
  help => "-c, --critical=INTEGER:INTEGER\n"
	. "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT\n"
	. "   for the threshold format",
  required => 0,
);

$np->add_arg(
  spec => 'performance|p',
  help => "-p, --performance\n"
    . "   Report performance data back to nagios",
  required => 0,
);

$np->getopts;

# Assign, then check args

my $verbose = $np->opts->verbose;

my($sensor) = 0;
$sensor = $np->opts->sensor if ( $np->opts->sensor );

my $community = "public";
$community = $np->opts->community if ( $np->opts->community );
print "community=$community\n" if ( $verbose );

my $hostname = $np->opts->hostname;
print "hostname=$hostname\n" if ( $verbose );

my(%thresholds) = ();
my $warning="";
if ( $np->opts->warning) {
        $warning = $np->opts->warning;
        $thresholds{warning} = $warning;
}

my $critical="";
if ( $np->opts->critical) {
        $critical = $np->opts->critical;
        $thresholds{critical} = $critical;
}
$np->set_thresholds( %thresholds );

my $performance = 0;
$performance = $np->opts->performance if ( $np->opts->performance );

my $list = 0;
$list = $np->opts->list if ( $np->opts->list );

$np->nagios_exit('UNKNOWN', 'Hostname contains invalid characters.')
  if ($hostname =~ /\`|\~|\!|\$|\%|\^|\&|\*|\||\'|\"|\<|\>|\?|\,|\(|\)|\=/);

# Just in case of problems, let's not hang Nagios
$SIG{ALRM} = sub {
    $np->nagios_exit(UNKNOWN, 'plugin timed out.');
};
alarm $np->opts->timeout;

####################################################################
# from the fantastic http://www.mibdepot.com/
# entPhysicalName OBJECT-TYPE	
#
#-- Rsyntax OCTET STRING(SIZE(0..255)) 
#-- 1.3.6.1.2.1.47.1.1.1.1.7
#-- iso(1). org(3). dod(6). internet(1). mgmt(2). mib-2(1).
#   entityMIB(47). entityMIBObjects(1). entityPhysical(1). 
#   entPhysicalTable(1). entPhysicalEntry(1). entPhysicalName(7)
# 	SYNTAX 	SnmpAdminString	 
# 	ACCESS 	read-only 	 
# 	DESCRIPTION   	 	 
# 	"The textual name of the physical entity.
####################################################################
my($descr_base) = ".1.3.6.1.2.1.47.1.1.1.1.7";
my($descr_oid) = $descr_base . "." . $sensor;
print "descr_oid=$descr_oid\n" if ( $verbose );

####################################################################
# from the fantastic http://www.mibdepot.com/
# entPhySensorValue OBJECT-TYPE	
#
#-- Rsyntax INTEGER(-1000000000..1000000000) 
#-- 1.3.6.1.2.1.99.1.1.1.4
#-- iso(1). org(3). dod(6). internet(1). mgmt(2). mib-2(1).
#   entitySensorMIB(99). entitySensorObjects(1). entPhySensorTable(1).
#   entPhySensorEntry(1). entPhySensorValue(4)
# 	SYNTAX 	EntitySensorValue	 
# 	ACCESS 	read-only 	 
# 	DESCRIPTION   	 	 
# 	"The most recent measurement obtained by the agent for this
#        sensor.
#
#       To correctly interpret the value of this object, the
#       associated entPhySensorType, entPhySensorScale, and
#       entPhySensorPrecision objects must also be examined."
####################################################################

my($value_base) = ".1.3.6.1.2.1.99.1.1.1.4";
my($value_oid) = $value_base . "." . $sensor;
print "value_oid=$value_oid\n" if ( $verbose );

####################################################################
# from the fantastic http://www.mibdepot.com/
# entPhySensorUnitsDisplay OBJECT-TYPE	
#
#-- Rsyntax OCTET STRING(SIZE(0..255)) 
#-- 1.3.6.1.2.1.99.1.1.1.6
#-- iso(1). org(3). dod(6). internet(1). mgmt(2). mib-2(1).
#   entitySensorMIB(99). entitySensorObjects(1). entPhySensorTable(1).
#   entPhySensorEntry(1). entPhySensorUnitsDisplay(6)
# 	SYNTAX 	SnmpAdminString	 
# 	ACCESS 	read-only 	 
# 	DESCRIPTION   	 	 
# 	"A textual description of the data units that should be used
#       in the display of entPhySensorValue."
####################################################################
my($unit_base) = ".1.3.6.1.2.1.99.1.1.1.6";
my($unit_oid) = $unit_base . "." . $sensor;
print "unit_oid=$unit_oid\n" if ( $verbose );


####################################################################
# from the fantastic http://www.mibdepot.com/
# entPhySensorOperStatus OBJECT-TYPE	 
#-- 1.3.6.1.2.1.99.1.1.1.5
#-- iso(1). org(3). dod(6). internet(1). mgmt(2). mib-2(1).
#   entitySensorMIB(99). entitySensorObjects(1). entPhySensorTable(1).
#   entPhySensorEntry(1). entPhySensorOperStatus(5)
# 	SYNTAX 	EntitySensorStatus	 
# 	MAX-ACCESS 	read-only 	 
# 	DESCRIPTION   	 	 
# 	"The operational status of the sensor."
#
#   SYNTAX  INTEGER  { 	 
# 		ok 	(1),	 
# 		unavailable 	(2),	 
# 		nonoperational 	(3)	 
# 	}
####################################################################
my($oper_base) = ".1.3.6.1.2.1.99.1.1.1.5";
my($oper_oid) = $oper_base . "." . $sensor;
print "oper_oid=$oper_oid\n" if ( $verbose );


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

if ( $list ) {
	my(%ent_oper) = trimhash( $session->get_table($oper_base) );
	my(%ent_descr) = trimhash( $session->get_table($descr_base) );
	my(%ent_value) = trimhash( $session->get_table($value_base) );
	my(%ent_unit) = trimhash( $session->get_table($unit_base) );
	my($sensor);
	foreach $sensor ( sort { $a <=> $b } keys %ent_oper ) {
		my($text) = "Sensor: $sensor, ";
		my($descr) = $ent_descr{$sensor};
		$text .= "$descr " if ( $descr );
		my($value) = $ent_value{$sensor};
		$text .= "current value: $value " if ( defined($value) );
		my($unit) = $ent_unit{$sensor};
		$text .= "($unit)" if ( defined($unit) );
		print $text . "\n";
	}
	exit(0);
}
	

my $result = $session->get_request(
	-varbindlist => [$oper_oid,$value_oid,$descr_oid,$unit_oid]
);

unless ( defined($result) ) {
	my($error) = $session->error;
	printf("ERROR: %s.\n", $error);
	$session->close;
	$np->nagios_exit('UNKNOWN',$error);
}

$session->close;

my($oper) = $result->{$oper_oid};
$oper = "0" unless ( defined($oper) );
print "oper=$oper\n" if ( $verbose );
unless ( $oper =~ /^1$/ ) {
	$np->nagios_exit('UNKNOWN',"Sensor: $sensor is not operational");
}

my($value) = $result->{$value_oid};
if ( $value ) {
	print "value=$value\n" if ( $verbose );
	if ( $value =~ /D/ ) {
		$np->nagios_exit('UNKNOWN',"Sensor: $sensor, non numeric value: $value");
	}
}

my($unit) = $result->{$unit_oid};
if ( $unit ) {
	print "unit=$unit\n" if ( $verbose );
}
else {
	$unit = "";
}

my($descr) = $result->{$descr_oid};
my($perfdescr);
if ( $descr ) {
	$perfdescr = $descr;
	$perfdescr =~ s/\s+/-/g;
	print "descr=$descr\n" if ( $verbose );
}
else {
	$descr = "SensorId-$sensor";
	$perfdescr = $descr;
	print "Could not find any description using: $descr\n" if ( $verbose );
}
my($perfstr) = $perfdescr . "=" . $value . $unit;
my($errorstr) = "Sensor: $sensor, $descr is $value ($unit)";
my($rc) = $np->check_threshold($value);
if ( $rc eq WARNING ) {
	$errorstr .= ", threshold is $warning";
}
elsif ( $rc eq CRITICAL ) {
	$errorstr .= ", threshold is $critical";
}
		
if ( $performance ) {
	$errorstr .= "| $perfstr";
}

$np->nagios_exit($rc,$errorstr);
