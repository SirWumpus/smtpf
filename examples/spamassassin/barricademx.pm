package Mail::SpamAssassin::Plugin::BarricadeMX;
my $VERSION = 0.1;

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

 my $header = $pms->get("X-smtpf-Report");
 if(defined($header)) {
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
