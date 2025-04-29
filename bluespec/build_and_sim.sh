#! /bin/bash
trap "echo; exit" INT
make bluesim 2>&1 | tee -a build.log;

mkdir ~/Dissertation-riga/simulations_v2/$1/$2;
mkdir ~/Dissertation-riga/simulations_v2/$1/$2/$3;
cp -r build ~/Dissertation-riga/simulations_v2/$1/$2;
cd sim-utils;
./run_sim.sh $1 $2 $3
