package Mail::SpamAssassin::Plugin::BarricadeMX;
my $VERSION = 0.2;

use strict;
use Mail::SpamAssassin::Plugin;
use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("BarricadeMX: @_");
}

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->register_eval_rule("bmx_get_sid");
}

sub bmx_get_sid {
 my ($self, $pms) = @_;

 # Get last external IP
 my $le = $pms->get_tag('LASTEXTERNALIP');
 if(defined($le) && $le) {
  dbg("Found last external IP: $le");
  $pms->set_spamd_result_item( sub { return "last-external=$le"; } );
 }

 my $header = $pms->get("X-smtpf-Report");
 if(defined($header) && $header) {
  dbg("Found header: $header");
  if($header =~ /^sid=(\S+);/) {
   my $sid = $1;
   dbg("Found session: $sid");
   $pms->set_spamd_result_item( sub { return "smtpf-session=$sid"; } );
   return 1;
  }
  return 0;
 }
 return 0;
}
