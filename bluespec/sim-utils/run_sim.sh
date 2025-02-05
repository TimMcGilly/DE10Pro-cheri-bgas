#! /bin/bash

NAME_OPTS=("adpcm_decode" "adpcm_encode" "aes" "basicmath" "blowfish" "crc" "dijkstra" "fft" "limits" "picojpeg" "qsort" "randmath" "rc4" "rsa" "sha")
BENCHMARK_NAME="adpcm_decode"

elfmanip.py -v -s 0xc0000000 -i 0x40000000 -o ~/Dissertation-riga/mibench2/$BENCHMARK_NAME/$BENCHMARK_NAME.hex ~/Dissertation-riga/mibench2/$BENCHMARK_NAME/$BENCHMARK_NAME.elf to-hex


export CHERI_BGAS_DDRB_HEX_INIT=~/Dissertation-riga/mibench2/$BENCHMARK_NAME/$BENCHMARK_NAME.hex
export CHERI_BGAS_PC_RESET_VALUE=0xc0000000
timeout --foreground 10m ./cheri-bgas-sim.py  -v --simulation-run-directory ./simulations/$BENCHMARK_NAME
