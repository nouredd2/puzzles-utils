set ns [new Simulator]
source tb_compat.tcl

set magi_start "sudo python /share/magi/current/magi_bootstrap.py"
set kernel_start "sudo /proj/ILLpuzzle/scripts/install_kernel.sh"

set Clients 2
set Attackers 1
set clanstr ""

for {set i 1 } {$i <= $Clients } { incr i } {
        set clientnode($i) [$ns node]
        tb-set-node-startcmd $clientnode($i) "$kernel_start"
        append clanstr "$clientnode($i) "
}

set alanstr ""

for {set i 1 } {$i <= $Attackers } { incr i } {
        set attacknode($i) [$ns node]
        tb-set-node-startcmd $attacknode($i) "$kernel_start"
        append alanstr "$attacknode($i) "
}

set slanstr ""

set A 1
for {set i 1 } {$i <= $A } { incr i } {
        set servernode($i) [$ns node]
        tb-set-node-startcmd $servernode($i) "$kernel_start"
        append slanstr "$servernode($i) "
}

set router [$ns node]
tb-set-node-startcmd $router "$magi_start"

set lanC [$ns make-lan "router $clanstr" 100Mb 0ms]
set lanS [$ns make-lan "router $slanstr" 100Mb 0ms]
set lanA [$ns make-lan "router $alanstr" 100Mb 0ms]

$ns rtproto Static
$ns run