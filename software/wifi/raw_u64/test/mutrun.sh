#!/bin/zsh
# Builds and runs every mutant in mutants/ (or the named ones), 4 at a time, and prints which cases each one fails.
# A mutant with no failing case survived: its tests have no teeth.  mutrun.sh [NAME...]
T=${0:A:h}; cd $T
names=(${@:-$(ls mutants/*.patch | xargs -n1 basename | sed 's/\.patch$//')})
one() {
  n=$1; k=$2
  ./build.sh mut-$n > build/mut-$n.build.txt 2>&1 || { echo "MUTANT $n BUILD-FAILED"; return; }
  PORTBASE=$((${MUTBASE:-24000} + k * 1000)) ./run.sh mut-$n > build/mut-$n/run.txt 2>&1
  killed=$(grep -E "^FAIL " build/mut-$n/run.txt | awk '{print $2}' | sort -u | tr '\n' ' ')
  if [ -n "$killed" ]; then echo "MUTANT $n KILLED by: $killed"; else echo "MUTANT $n SURVIVED"; fi
}
i=0
for n in $names; do
  one $n $((i % 4)) &
  i=$((i + 1))
  (( i % 4 == 0 )) && wait
done
wait
