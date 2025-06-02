#! /bin/bash

set -Eeuo pipefail

if [[ $# -eq 0 ]] ; then
    echo 'No arugments passed arguments'
    exit 1
fi

cd ../../
rsync -ahv --exclude bluespec/Toooba/builds/Resources --exclude bluespec/sim-utils/analyse/ --exclude bluespec/build/ --exclude bluespec/.depends.mk DE10Pro-cheri-bgas/ DE10Pro-cheri-bgas-no-prefetcher
# rsync -ahv --exclude bluespec/Toooba/builds/Resources --exclude bluespec/sim-utils/analyse/ --exclude bluespec/build/ --exclude bluespec/.depends.mk DE10Pro-cheri-bgas/ DE10Pro-cheri-bgas-logging-prefetcher

(cd ./DE10Pro-cheri-bgas/bluespec;
./build_and_sim.sh $1 $2;
cd ../../;) #&

# (sleep 10s;
# cd ./DE10Pro-cheri-bgas-logging-prefetcher/bluespec/;
# ./build_and_sim.sh logging-prefetcher $1 $2 $3 $4;
# cd ../../;)&

# (sleep 20s;
# cd ./DE10Pro-cheri-bgas-no-prefetcher/bluespec/;
# ./build_and_sim.sh without-prefetcher $1 $2 $3 $4)

