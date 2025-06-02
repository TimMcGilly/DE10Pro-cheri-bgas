#! /bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'No arugments passed arguments'
    exit 1
fi


for benchmark in bh bisort em3d health perimeter power treeadd tsp; do
    (./run_all_sims.sh $1 $2 $benchmark olden-baremetal-cheri-riscv $benchmark)&
    sleep 60s
done