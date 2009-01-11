#!/usr/bin/perl -w
#
# BarricadeMX
# Copyright 2009; Fort Systems Ltd.
#

use strict;
use File::Copy;

# Prevent multiple copies of this script from running
use Fcntl ':flock';
open(SELF, "<", $0) or die "Can't open self: $!";
flock SELF, LOCK_EX | LOCK_NB or exit;

my(%config);
my(%hosters);
my($cfg_dir) = '/etc/smtpf';
my($make) = '/usr/bin/make';
my($wget) = '/usr/bin/wget';
my($smtpf) = '/usr/sbin/smtpf';
my($hosters_file) = "$cfg_dir/hosters.txt";
my($hosters_url) = "http://rss.uribl.com/hosters/hosters.txt";
my($tlds_file) = "$cfg_dir/two-level-tlds";
my($tlds_url) = "http://spamcheck.freeapp.net/two-level-tlds";
my($tlds_merge_file) = "$cfg_dir/two-level-tlds-combined";
my($debug) = 0;

# Read smtpf.cf
open(FILE, "< $cfg_dir/smtpf.cf") or die $!;
while(<FILE>) {
 next if (/^(#|$|\s+$)/);
 if(/^([a-z\-\+_]+)=(.*)/) {
  $config{$1} = $2;
 }
 if(/^([a-z\-_]+)\+=(.*)/) {
  $config{$1} .= ";$2";
 }
}
close(FILE) or die $!;

# Check that URIBL is being used
if(defined($config{'uri-bl'}) && $config{'uri-bl'} =~ /\.uribl\.com/) {
 # Introduce a random delay if up to an hour
 my($updatemaxdelay) = 3600;
 my($delay) = int(rand($updatemaxdelay));
 # No delay if any arguments are passed to allow for interactive runs
 if(not defined($ARGV[0])) {
  my($saved_ps) = $0;
  $0 .= ": sleeping $delay sec";
  print STDERR "Sleeping for $delay seconds.\n" if $debug;
  sleep $delay;
  $0 = $saved_ps;
 }

 my $update_required = 0;
 $update_required = 1 if(download($hosters_url, $hosters_file));
 $update_required = 1 if(download($tlds_url,$tlds_file));
 if($update_required) {
  print STDERR "Updates found.\n" if $debug;
  # Create a new combined file
  open(COM, "> $tlds_merge_file") or die $!;
  my $datetime = localtime;
  # Add two-level-tlds
  open(TLD, "< $tlds_file") or die $!;
  while(<TLD>) {
   print COM $_;
  }
  close(TLD) or die $!;
  # Add hosters.txt file
  open(HOST, "< $hosters_file") or die $!;
  while(<HOST>) {
   print COM $_;
   chomp;
   $hosters{$_} = 1; 
  }
  close(HOST) or die $!;
  close(COM) or die $!;

  # Filter access.cf
  if(-e "$cfg_dir/access.cf") {
   filter_file("$cfg_dir/access.cf", "$cfg_dir/access.cf.new");
  }
  
  # Filter access-defaults.cf
  if(-e "$cfg_dir/access-defaults.cf") {
   filter_file("$cfg_dir/access-defaults.cf", "$cfg_dir/access-defaults.cf.new");
  }

  # Make maps
  system("$make -C$cfg_dir 2>&1 > /dev/null");
  if($? == -1 && ($? >> 8) != 0) {
   die $!;
  } else {
   print STDERR "Make ran successfully.\n" if $debug;
  }
 
  # If the merge file exists and tld-level-two-file is not
  # configured, re-write smtpf.cf and set tld-level-two-file.
  if(-e $tlds_merge_file && ((defined($config{'tld-level-two-file'}) && $config{'tld-level-two-file'} ne $tlds_merge_file))) {
   print STDERR "Updating tld-level-two-file in smtpf.cf.\n" if $debug;
   open(SMTPF, "< $cfg_dir/smtpf.cf") or die $!;
   open(NSMTPF, "> $cfg_dir/smtpf.cf.new") or die $!;
   while(<SMTPF>) {
    if(/^tld-level-two-file=/ && !/$tlds_merge_file/) {
     print NSMTPF "tld-level-two-file=$tlds_merge_file\n";
    } else {
     print NSMTPF $_;
    }
   }
   close(SMTPF) or die $!;
   close(NSMTPF) or die $!;
   move("$cfg_dir/smtpf.cf.new","$cfg_dir/smtpf.cf") or die $!;
  }

  # Phew - we're done; restart smtpf
  system("$smtpf +restart");
  if($? == -1 && ($? >> 8) != 0) {
   die $!;
  } else {
   print STDERR "smtpf restarted.\n" if $debug;
  }
 } else {
  print STDERR "Update not required.\n" if $debug;
 }
} else { 
 if($debug) {
  print STDERR "Skipping run as uribl.com is not used in uri-bl list.\n";
 }
}

sub download {
 my($remote_url,$local_file) = @_;
 die if (!$remote_url or !$local_file);

 my($pre_mtime) = ((stat $local_file)[9] or 0);
 system("$wget -q -N -O $local_file $remote_url");
 if($? == -1) {
  die "Command failed: $!\n";
 } else {
  if(($?>>8) != 0) {
   die "Command returned ".($?>>8)."\n";
  }
 }
 my($post_mtime) = (stat $local_file)[9];
 if($pre_mtime != $post_mtime) {
  # File updated
  return 1;
 }
 return 0;
}

sub filter_file {
 my($input_file, $output_file) = @_;
 die if (!$input_file or !$output_file);
 my($updated) = 0;
 open(INPUT, "< $input_file") or die $!;
 open(OUTPUT, "> $output_file") or die $!;
 while(<INPUT>) {
  chomp;
  my($line) = lc($_);
  $line =~ s/\s+/ /;
  if(my($uri, $action) = $line =~ /body:(\S+)\s(\S+)/i) {
   if($action eq 'ok' && defined($hosters{$uri})) {
    # Skip this entry
    $updated = 1;
    print STDERR "Removing $uri from $input_file\n" if $debug;
   } else {
    print OUTPUT "$_\n";
   }
  } else {
   print OUTPUT "$_\n";
  }
 }
 close(INPUT) or die $!;
 close(OUTPUT) or die $!; 
 if($updated) {
  move($output_file, $input_file) or die $!;
 } else {
  unlink($output_file) or die $!;
 }
}
