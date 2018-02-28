#!/bin/bash

OUT_FILE="../experiments/test_exp_increasing_diff.yaml"

OUT=''

for difficulty in "$@"
do
    OUT+="- type: event
        agent: change_difficulty_agent
        method: setConfiguration
        args: { cmdstring: \"/proj/ILLpuzzle/scripts/set_difficulty.sh $difficulty\" }
      - type: event
        agent: change_difficulty_agent
        method: start
        args: {}
      "
    OUT+="- type: trigger
        triggers: [ { timeout: 60000 } ]

      "
done

echo "$OUT"
# sed "8 a $OUT" $OUT_FILE

# sed -i "s/trigger: serverStarted args: {} /a\
# $OUT" $OUT_FILE
