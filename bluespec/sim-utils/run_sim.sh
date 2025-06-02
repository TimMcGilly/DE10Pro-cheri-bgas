#! /bin/bash

set -Eeuo pipefail

if [[ $# -eq 0 ]] ; then
    echo 'No arugments passed arguments'
    exit 1
fi

if [[ -z "$5" ]] ;  then
    echo 'Needs 5 arugments'
    exit 1
fi

BENCHMARK_ROOT=$4
BENCHMARK_NAME=$5

elfmanip.py -v -s 0xc0000000 -i 0x40000000 -o ~/Dissertation-riga/$BENCHMARK_ROOT/$BENCHMARK_NAME/$BENCHMARK_NAME.hex ~/Dissertation-riga/$BENCHMARK_ROOT/$BENCHMARK_NAME/main.elf to-hex


export CHERI_BGAS_DDRB_HEX_INIT=~/Dissertation-riga/$BENCHMARK_ROOT/$BENCHMARK_NAME/$BENCHMARK_NAME.hex
export CHERI_BGAS_PC_RESET_VALUE=0xc0000000
(sleep 630m; killall -9 cheri-bgas-fuse-devfs) & ((timeout --foreground 10h ./cheri-bgas-sim.py  -v --simulation-run-directory ~/Dissertation-riga/simulations_v2/$1/$2/$3 --simulation-build-dir ~/Dissertation-riga/simulations_v2/$1/$2/build/simdir/sim_CHERI_BGAS);pigz ~/Dissertation-riga/simulations_v2/$1/$2/$3/sim_0.0/sim_stdout)
# cd analyse
# python3 analyse_log.py -i $2/$3 -u 1000000 > ~/Dissertation-riga/simulations_v2/results/$2/$3/1000000.txt
# python3 analyse_log.py -i $2/$3 -u 4000000 > ~/Dissertation-riga/simulations_v2/results/$2/$3/4000000.txt
