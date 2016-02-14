#!/usr/bin/perl -w

$|=1;
use strict;
use File::Copy;
use Fcntl ':flock';

# Prevent multiple copies from running concurrently
open(SELF, "<", $0) or die "Can't open self: $!";
flock SELF, LOCK_EX | LOCK_NB or exit;

my($trapdir);
open(CF, '< /etc/smtpf/smtpf.cf') or die $!;
while(<CF>) {
 last if(($trapdir) = $_ =~ /^trap-dir=(\S+)$/);
}
close(CF) or die $!;
die "Trap directory not configured!" if(!defined($trapdir));
die "Trap directory ($trapdir) does not exist!" if(! -d $trapdir);

# Move files
my($count) = 0;
mkdir "$trapdir/work/" if (! -d "$trapdir/work/");
while(my $file = <$trapdir/*.trap>) {
 move($file, "$trapdir/work/") or die $!;
 $count++;
}

my($info) = join("",time(),":$count");
print STDOUT "$info\n";
exit(0) if $count eq 0;

## SA-Learn
open(CMD, '/usr/bin/sa-learn --dump magic 2>&1 |') or die $!;
my(%magic);
while(<CMD>) {
 # 0.000          0     313843          0  non-token data: nspam
 # 0.000          0    2148254          0  non-token data: nham
 if(my($val, $key) = $_ =~ /^\S+\s+\S+\s+(\S+)\s+\S+\s+non-token data: (.+)$/) {
  $key =~ s/\s+//g;
  $magic{$key} = $val;
 }
}
close(CMD) or die $!; 
die "Error retrieving magic!" if (!defined($magic{'nham'}) || !defined($magic{'nspam'}));

my($total) = int ($magic{'nspam'} + $magic{'nham'});
my($pctspam) = sprintf("%.2f",(($magic{'nspam'}/$total)*100));
print STDERR "Training data: $total messages, $pctspam% spam.\n";

if($magic{'nspam'} < $magic{'nham'}) {
 # Run sa-learn and delete files
 system("/usr/bin/sa-learn --spam $trapdir/work/*.trap 1> /dev/null");
} else {
 print STDERR "Not running sa-learn as spam > ham\n";
}

# Nuke files
my $cnt = unlink(<$trapdir/work/*.trap>);
