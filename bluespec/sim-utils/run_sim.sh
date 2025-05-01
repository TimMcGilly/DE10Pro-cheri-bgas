#! /bin/bash
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
timeout --foreground 4h ./cheri-bgas-sim.py  -v --simulation-run-directory ~/Dissertation-riga/simulations_v2/$1/$2/$3 --simulation-build-dir ~/Dissertation-riga/simulations_v2/$1/$2/build/simdir/sim_CHERI_BGAS