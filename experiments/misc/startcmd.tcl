# This is a simple ns script. Comments start with #.
set ns [new Simulator]
source tb_compat.tcl

set kernel_install "sudo /proj/ILLpuzzle/scripts/install_kernel.sh"

set nodeA [$ns node]

tb-set-node-os $nodeA Ubuntu1604-STD
tb-set-node-startcmd $nodeA $kernel_install

# Go!
$ns run
