#! /usr/bin/perl -w

use strict;
use warnings;
use vars qw($PROGNAME $VERSION);
use FileHandle;
use File::Basename qw(basename);
use Nagios::Plugin;
use Digest::MD5;

$VERSION = '0.1.6';

##########################################################################################
##########################################################################################
##########################################################################################
#
# check_events  -  Search logfiles for down & up events
# Written by Peter Wirdemo (peter <dot> wirdemo gmail <dot> com)
# 
# Inspired by Aaron Bostick's check_log2,
# which was inspired by Ethan Galstad check_log.
#
# Latest version can be found at
# http://sites.google.com/site/peterwirdemo/home/nagios-plugins/check_events.pl
#
#########
# Version
#########
#
# 0.1.6 2010-08-31
# Added support for inode change, patch by Francesco Pedrini
#
##############
# Description: 
##############
#
# This plugin will scan arbitrary text files looking for down and up events.
# The events are searched using Perl regular expressions. When a down event is found,
# the plugin exits with either WARNING (-W) or CRITICAL (-C). This is ideal for
# searching an snmp trap logfile. The plugin can run i two modes:
#
#  1) Default mode
#     When both a down event and an up event are added to the logfile since the
#     last run the plugin will exit with an OK, i.e you have missed the glitch.
#
#  2) Glitch mode ( -G | --glitch )
#     When both a down event and an up event are added to the logfile since the 
#     last run the plugin will exit with WARNING or CRITICAL depending on the
#     -W (warning) and -C (critical) flag. The next run of the plugin will
#     start the search for new events after the <last> down event. This can be
#     useful when the glitch is shortlived.
#
########
# Usage:
########
#
# check_events.pl [ -W (warning) ] [ -C (critical)> ] [ -L <log filename> ] [ -S <seek filename> ] [ -D <down event text> ] [ -U <up event text> ]
#
#   -?, --usage
#     Print usage information
#   -h, --help
#     Print detailed help screen
#   -V, --version
#     Print version information
#   --extra-opts=[<section>[@<config_file>]]
#     Section and/or config_file from which to load extra options (may repeat)
#   -W, --warning
#     Report Warning if down event text is found (default)
#   -C, --critical
#     Report Critical if down event text is found
#   -L, --logfile
#     Filename to read and parse
#   -S, --seekfile
#     Filename to store last pos and other runtime things
#     If not specified, it is computed using an md5 hash of the down & up
#     event and slightly modified name of the logfile. Example:
#     "/var/tmp/check_events/<logfile>.seekfile.<md5hash>"
#   -D, --downevent
#     Regular expression, matching the down event text
#   -U, --upevent
#     Regular expression, matching the down event text
#   -G, --glitch
#     Enable glitch finding mode, when a new down event is found
#     exit with a WARNING or CRITICAL status and save the file position.
#     Next time the plugin executes, start the scan at the line after
#     down event.
#   -t, --timeout=INTEGER
#     Seconds before plugin times out (default: 30)
#   -v, --verbose
#     Show details for command-line debugging (can repeat up to 3 times)
#   
#
#
#########
# Output:
#########
#
# This plugin returns OK when a file is successfully scanned and no pattern
# matches are found or when only up events are found.
# If only down events are found, WARNING or CRITITCAL will be returned, depending
# on the -W | --warning and -C | --critical flags. WARNING is the default.
# Consequently executions of the plugin will return the last status until
# an up event is found in the logfile.
#
#  If you specify a seekfile, 
#     You *must* supply a different <seekfile> for each service that
#     you define to use this plugin script - even if the different services
#     check the same <logfile> for pattern matches.  This is necessary
#     because of the way the script operates.
#
#
###########
# Examples:
###########
#
# check_events.pl -L /var/log/snmptrapd.log -D "utility power failure" -U "utility power restored"
#
# Example output:
#   check_events.pl CRITICAL - SNMPv2-SMI::enterprises.318.2.3.3.0 "UPS: Switched to battery backup power; utility power failure."
#
# Example content of a seekfile (/var/log/check_events/_var_log_snmptrapd_log.seekfile.28cf8cb1cc203a6a820121bc0a4b720e)
#   SNMPv2-SMI::enterprises.318.2.3.3.0 "UPS: Switched to battery backup power; utility power failure."
#   #param# pos=2504
#   #param# state=2
#   #param# fsize=2504
#
##########################################################################################
##########################################################################################
##########################################################################################


my $verbose = 0;

##########################################################################################
# debug:
# Print debug/verbose messages.
# Parameter 1: $msglvl ( in which debug level should this message be printed )
# Alla other parameters are concatenated and printed.
# debug(2,"This will only be printed"," if $verbose (", $verbose, ") is 2 or more...");
##########################################################################################
sub debug {
	my($msglvl) = shift;
	my($dbgmsg) = join(" ",@_);
	return unless ( $dbgmsg );
	chomp($dbgmsg);
	print "DEBUG($msglvl): $dbgmsg\n" if ( $msglvl <= $verbose );
}


##########################################################################################
# seekfile:
# Create a filename for storing runtime data
# Parameter 1: $filename ( base filename )
# All other parameters are added to a md5 hash
##########################################################################################
sub seekfile ($$;) {
	my($filename) = shift;
	debug(2,"seekfile:filename=$filename");
	$filename =~ s/\W/_/g;

	my($ctx);
	$ctx = Digest::MD5->new;
	$ctx->add($filename);
        foreach ( @_ ) {
                $ctx->add($_);
        }

	my($basedir) = "/var/tmp/check_events";
	if ( ! -d $basedir ) {
		mkdir ($basedir);
	}
	$filename = $basedir . "/" . $filename . ".seekfile." . $ctx->hexdigest();
	debug(2,"seekfile:seekfile=$filename");
	return($filename);
}
	
	

$PROGNAME = basename($0);

my $np = Nagios::Plugin->new(
  usage => "Usage: %s -G -W|-C -L <log filename> -S <seek filename> -D <down event text> -U <up event text>\n",
  version => $VERSION,
  plugin  => $PROGNAME,
  shortname => $PROGNAME,
  blurb => 'Check for down & up events in a logfile',
  extra   => "\n\nCopyright (c) Peter Wirdemo",
  timeout => 30,
);

$np->add_arg(
  spec => 'warning|w',
  help => "-W, --warning\n"
    . "   Report Warning if down event text is found (default)",
  required => 0,
);

$np->add_arg(
  spec => 'critical|c',
  help => "-C, --critical\n"
    . "   Report Critical if down event text is found",
  required => 0,
);

$np->add_arg(
  spec => 'logfile|L=s',
  help => "-L, --logfile\n"
    . "   Filename to read and parse",
  required => 1,
);

$np->add_arg(
  spec => 'seekfile|S=s',
  help => "-S, --seekfile\n"
    . "    Filename to store last pos and other runtime things\n"
    . "    If not specified, it is computed using a md5 hash of the down & up\n"
    . "    event and slightly modified name of the logfile. Example:\n"
    . "    \"/var/tmp/check_events/<logfile>.seekfile.<md5hash>\"",
  required => 0,
);

$np->add_arg(
  spec => 'downevent|D=s',
  help => "-D, --downevent\n"
    . "   Regular expression, matching the down event text",
  required => 1,
);

$np->add_arg(
  spec => 'upevent|U=s',
  help => "-U, --upevent\n"
    . "   Regular expression, matching the down event text",
  required => 1,
);

$np->add_arg(
  spec => 'glitch|G',
  help => "-G, --glitch\n"
    . "   Enable glitch finding mode, when a new downevent is found\n"
    . "   exit with a WARNING or CRITICAL status and save the file position.\n"
    . "   Next time the plugin executes, start the scan at the line after\n"
    . "   downevent.",
  required => 0,
);

$np->add_arg(
  spec => 'message|M=s',
  help => "-M, --message\n"
    . "   Prints <message> on stdout when an downevent is found\n"
    . "   (...instead of the content of the downevent...)",
  required => 0,
);
$np->getopts;

# Assign, then check args

$verbose = $np->opts->verbose if ( $np->opts->verbose );
debug(1, "verbose=$verbose");

my $glitch = $np->opts->glitch;
debug(1, "glitch=$glitch\n") if ( $glitch );

my $warning = $np->opts->warning;
debug(1, "warning=$warning\n") if ( $warning );

my $critical = $np->opts->critical;
debug(1, "critical=$critical\n") if ( $critical );

my $message = $np->opts->message;
debug(1, "message=$message\n") if ( $message );

my $logfile = $np->opts->logfile;
debug(1, "logfile=$logfile\n") if ( $logfile );

my $upevent = $np->opts->upevent;
eval { if ( "bepa" =~ /$upevent/ ) {} };
$np->nagios_exit(UNKNOWN, $@ ) if $@;
debug(1, "upevent=$upevent\n") if ( $upevent );

my $downevent = $np->opts->downevent;
eval { if ( "bepa" =~ /$downevent/ ) {} };
$np->nagios_exit(UNKNOWN, $@ ) if $@;
debug(1, "downevent=$downevent\n") if ( $downevent );

my $seekfile = $np->opts->seekfile;
unless ( $seekfile ) {
	$seekfile = seekfile($logfile, $upevent . $downevent );
}
debug(1, "seekfile=$seekfile\n") if ( $seekfile );


# Just in case of problems, let's not hang Nagios
$SIG{ALRM} = sub {
    $np->nagios_exit(UNKNOWN, 'plugin timed out.');
};
alarm $np->opts->timeout;

my $fh = new FileHandle;
unless ($fh->open("< $logfile")) {
    $np->nagios_exit(OK, "Reading $logfile: $!\n" );
}

my $curr_fsize = (stat($fh))[7];
debug(1, "curr_fsize($logfile) = $curr_fsize\n") if ( $curr_fsize );

my $curr_inode = (stat($fh))[1];
debug(1, "curr_inode($logfile) = $curr_inode\n") if ( $curr_inode );


my($prev_pos) = 0;
my($prev_fsize) = 0;
my($prev_state) = 0;
my($prev_inode) = undef;
my($prev_text) = undef;
my($param) = "#param#";
my $sh = new FileHandle;
if ( $sh->open("<$seekfile") ) {
	my($line);
	while( ! $sh->eof() ) {
		$line = $sh->gets();
		chomp($line);
		if ( $line =~ /^$param\s/ ) {
			$line =~ s/^$param\s+//;
			$line =~ s/^\s+//;
		}
		else {
			$prev_text .= $line;
			next;
		}
		foreach ( split(/\s+/,$line) ) {
			my($key,$value) = split(/=/,$_);
			if ( $key eq "pos" ) {
				$prev_pos = $value;
			}
			elsif ( $key eq "fsize" ) {
				$prev_fsize = $value;
			}
			elsif ( $key eq "state" ) {
				$prev_state = $value;
			}
			elsif ( $key eq "inode" ) {
				$prev_inode = $value;
			}
		}
	
	}
	$sh->close();

	debug(1, "prev_text (from seekfile) = $prev_text\n");

	$prev_pos = 0 unless ( $prev_pos );
	debug(1, "prev_pos (from seekfile) = $prev_pos\n");
	$prev_fsize = 0 unless ( $prev_fsize );
	debug(1, "prev_fsize (from seekfile) = $prev_fsize\n");
	$prev_state = 0 unless ( $prev_state );
	debug(1, "prev_state (from seekfile) = $prev_state\n");

	if ( $curr_inode != $prev_inode ) { # The file has changed so ignore the prev_pos and start over...
		$prev_pos = 0;
		debug(1, "prev_pos (changed: curr_inode != prev_inode) = $prev_inode -> $curr_inode\n");
	}
	elsif ( $prev_fsize > $curr_fsize ) { # File size was larger before, turnaround or something...
		$prev_pos = 0; 
		debug(1, "prev_pos (changed: prev_fsize > curr_fsize) = $prev_pos\n");
	}
	elsif ( $curr_fsize < $prev_pos ) { # File size is less the last prev_pos, tunraround or something...
		$prev_pos = 0;
		debug(1, "prev_pos (changed: curr_fsize < prev_pos) = $prev_pos\n");
	}
}

	
my($curr_pos) = $prev_pos;
unless ( seek($fh,$curr_pos,0) ) {
	unless ( seek($fh,0,0) ) {
		$np->nagios_exit(UNKNOWN, "seek: $!" );
	}
}

my($found_downevent) = 0;
my($last_downevent_pos) = $curr_pos;
my($last_downevent_text) = "";
my($state_change) = 0;
my($foundevent) = 0;
my($curr_text) = undef;
while( ! $fh->eof() ) {
	my($line) = $fh->gets();
	$curr_pos = tell($fh);
	if ( $line =~ /$downevent/ ) {
		$foundevent = 1;
		$state_change = 1;
		if ( $message ) {
			$curr_text = $message;
		}
		else {
			$curr_text = $line;
		} 

		#
		# If we want to report that an downevent has occured, but 
		# there can be upevents after...
		# I.e we can alert on short glitches...

		$found_downevent = 1;
		$last_downevent_pos = $curr_pos;	# Save file position of last error
		$last_downevent_text = $curr_text;	# Save the last error message
	}
	elsif ( $line =~ /$upevent/ ) {
		$curr_text = "No event found";
		$foundevent = 0;
		$state_change = 1;
	}
	debug(2, "foundevent=$foundevent\n");
}
$fh->close();

if ( $glitch ) {
	if ( $found_downevent ) {
		$foundevent = 1;
		$curr_text = $last_downevent_text;
		$curr_pos = $last_downevent_pos
	}
}

unless ( $prev_text ) {
	$prev_text = "No event found";
}

if ( $curr_text ) {
	chomp($curr_text);
}
else {
	$curr_text = "No event found";
}


#Turn off alarm
alarm(0);
my($curr_state) = $prev_state;
my($text) = $prev_text;
if ( $state_change ) {
	$text = $curr_text;
	if ( $foundevent ) {
		$curr_state = WARNING;
		$curr_state = CRITICAL if ( $critical );	
	}
	else {
		$curr_state = OK;
	}
}

my($seektext) = "";
$seektext .= $text . "\n";
$seektext .= "$param pos=$curr_pos\n";
$seektext .= "$param state=$curr_state\n";
$seektext .= "$param fsize=$curr_fsize\n";
$seektext .= "$param inode=$curr_inode\n";

if ($sh->open("> $seekfile")) {
	print $sh $seektext;
	$sh->close;
}
else {
	$curr_state = UNKNOWN;
	$text = "$!, writing stateinfo to $seekfile\n";
}

$np->nagios_exit($curr_state, $text);
