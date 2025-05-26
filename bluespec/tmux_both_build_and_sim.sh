tmux new-session -d -s tm746-$1 "./both_build_and_sim.sh $1 $2 $3 $4; sleep 100m"
