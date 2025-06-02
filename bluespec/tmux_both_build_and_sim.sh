tmux new-session -d -s tm746-$1-$2 "./both_build_and_sim.sh $1 $2; sleep 24h"
