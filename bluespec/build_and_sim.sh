#! /bin/bash
trap "echo; exit" INT

set -Eeuo pipefail

make bluesim 2>&1 | tee build.log;

mkdir ~/Dissertation-riga/simulations_v2/$1/$2;
cp -r build ~/Dissertation-riga/simulations_v2/$1/$2;
cp build.log ~/Dissertation-riga/simulations_v2/$1/$2/build.log;
cd sim-utils;
./run_all_olden_benchmarks.sh $1 $2