#! /bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'No arugments passed arguments'
    exit 1
fi

mkdir ~/Dissertation-riga/simulations_v2/results/$1;

for benchmark in bh bisort em3d health perimeter power treeadd tsp; do
    (mkdir ~/Dissertation-riga/simulations_v2/results/$1/$benchmark;
    ./run_all_sims.sh $1 $benchmark olden-baremetal-cheri-riscv $benchmark)&
    sleep 60s
done