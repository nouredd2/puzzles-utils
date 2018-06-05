set ns [new Simulator] 
source tb_compat.tcl 

set magi_start "sudo python /share/magi/current/magi_bootstrap.py"
set kernel_start "sudo /proj/ILLpuzzle/scripts/install_kernel.sh" 

set Clients 15 
set Attackers 10


# Client LAN 1
set clanstr1 ""
for {set i 1 } {$i <= 5 } { incr i } {   
        set clientnode($i) [$ns node]
        tb-set-node-startcmd $clientnode($i) "$kernel_start" 
        append clanstr1 "$clientnode($i) "
}

# Client LAN 2
set clanstr2  ""
for {set i 6 } {$i <= 10} { incr i } {
        set clientnode($i) [$ns node]
        tb-set-node-startcmd $clientnode($i) "$kernel_start" 
        append clanstr2 "$clientnode($i) "
}

# Client LAN 3
set clanstr3  ""
for {set i 11 } {$i <= 15} { incr i } {
        set clientnode($i) [$ns node]
        tb-set-node-startcmd $clientnode($i) "$kernel_start" 
        append clanstr3 "$clientnode($i) "
}

# Attack LAN 1
set alanstr1 ""
for {set i 1 } {$i <= 5 } { incr i } {   
        set attacknode($i) [$ns node]
        tb-set-node-startcmd $attacknode($i) "$kernel_start" 
        append alanstr1 "$attacknode($i) "
}  

# Attack LAN 2
set alanstr2 ""
for {set i 6 } {$i <= 10 } { incr i } {   
        set attacknode($i) [$ns node]
        tb-set-node-startcmd $attacknode($i) "$kernel_start" 
        append alanstr2 "$attacknode($i) "
}  

# Http server
set slanstr ""
set servernode [$ns node]
tb-set-node-startcmd $servernode "$kernel_start"
append slanstr "$servernode"

# magi node
set alanstr  ""
set amaginode [$ns node]
tb-set-node-startcmd $amaginode "$kernel_start"
append alanstr "$amaginode"
tb-set-sync-server $amaginode

# Routers
set router1 [$ns node] 
tb-set-node-startcmd $router1 "$magi_start"

set router2 [$ns node] 
tb-set-node-startcmd $router2 "$magi_start"

set router3 [$ns node] 
tb-set-node-startcmd $router3 "$magi_start"

set lanC1 [$ns make-lan "router1 $clanstr1" 100Mb 0ms]
set lanC2 [$ns make-lan "router1 $clanstr2" 100Mb 0ms]
set lanA1 [$ns make-lan "router1 $alanstr1" 100Mb 0ms]

set lanC3 [$ns make-lan "router3 $clanstr3" 100Mb 0ms]
set lanA2 [$ns make-lan "router3 $alanstr2" 100Mb 0ms]

set lanS [$ns make-lan "router2 $slanstr" 1000Mb 0ms]
set lanK [$ns make-lan "router2 $alanstr" 1000Mb 0ms]

set link1 [$ns duplex-link $router1 $router2 100Mb 0ms DropTail]
set link2 [$ns duplex-link $router2 $router3 100Mb 0ms DropTail]

$ns rtproto Static
$ns run 
