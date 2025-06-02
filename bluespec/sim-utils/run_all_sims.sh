#! /bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'No arugments passed arguments'
    exit 1
fi

(./run_sim.sh $1 $2 $3 $4 $5;)
# (sleep 20s;
# ./run_sim.sh logging-prefetcher $1 $2 $3 $4;)&
# (sleep 25s;
# ./run_sim.sh without-prefetcher $1 $2 $3 $4)