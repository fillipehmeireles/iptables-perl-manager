#!/usr/bin/perl


use IPTables::ChainMgr;
use YAML::XS qw(LoadFile);


%tables = qw(
	FILTER filter
	NAT nat
	MANGLE mangle
);

$ipt_bin = '/sbin/iptables';
$firewall_config = LoadFile('firewall.yaml');

sub default_filter_policy {
		my $table = $tables{FILTER};
		my @chains = ('INPUT','FORWARD','OUTPUT');
		my $policy = 'ACCEPT';
		foreach (@chains) {
			($rv) = ($_[0]->set_chain_policy($table,  $_ , $policy))[0];
			$rv == 0 ? print "[!] ($table/$_) > Error on Setting policy $policy \n" : print "[*] ($table/$_) > Setting policy $policy \n";
		}
}

sub ssh_access {
	my $chain = 'INPUT';
	my $policy = 'ACCEPT';
	($rv, $out_ar, $errs_ar) = $_[0]->append_ip_rule('0/0',
    '0/0', $tables{FILTER}, $chain, $policy,
    {'protocol' => 'tcp','d_port' => 22});
}

sub show_filter_rules {
	my ($rv, $out_ar, $errs_ar) = $_[0]->run_ipt_cmd("${ipt_bin} -nvL");
	print "\n@$out_ar";
}

%options = (
		'use_ipv6' => $firewall_config->{ipv6},
		'ipt_rules_file' => $firewall_config->{rules_file},
		'debug' => $firewall_config->{debug},
		'verbose' => $firewall_config->{verbose},
		'ipt_alarm' => $firewall_config->{alarm_ipt_exec},
		'ipt_exec_style' => $firewall_config->{exec_style},
		'ipt_exec_sleep' => $firewall_config->{timeout_ipt_exec},
);

$ipt = IPTables::ChainMgr->new(%options) or die "[!] Could not acquire IPTables obj";

default_filter_policy($ipt);
show_filter_rules($ipt);
ssh_access($ipt);
