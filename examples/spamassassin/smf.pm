package Mail::SpamAssassin::Plugin::SMF;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_line_length");
  $self->register_eval_rule("check_ma_html_first");
  return $self;
}

sub check_line_length {
  my ($self, $pms) = @_;

  my $line_count = 0;
  my $min_length = 0;
  my $avg_length = 0;
  my $max_length = 0;
  my $tot_length = 0;
  # foreach my $line (@pristine) {
  foreach my $line (split(/\n/s, $pms->{msg}->get_pristine)) {
   my $length = length($line);
   $min_length = $length if(($length > 0) && ($length < $min_length));
   $max_length = $length if($length > $max_length);
   $tot_length += $length;
   $line_count++;
  }
  $avg_length = $tot_length / $line_count;
  dbg('check_line_length: min='.$min_length.', max='.$max_length.', avg='.$avg_length.', total='.$tot_length.', lines='.$line_count);
  if($max_length <= 1000) {
   return 0;
  } else {
   return 1;
  }
}

sub check_ma_html_first {
  my($self, $pms) = @_;
  my($got_plain) = 0;

  foreach my $map ($pms->{msg}->find_parts(qr@^multipart/alternative$@i)) {
    $got_plain = 0;
    foreach my $p ($map->find_parts(qr/./, 1, 0)) {
      dbg('Found multipart/alternative part: '.lc($p->{'type'}));
      $got_plain = 1 if (lc $p->{'type'} eq 'text/plain');
      return 1 if (!$got_plain && (lc $p->{'type'} eq 'text/html'));
    }
  }
  
  return 0;
}


1;
