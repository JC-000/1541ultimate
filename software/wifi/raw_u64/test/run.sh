#!/bin/zsh
# Runs the engine host test: run.sh VARIANT [CASE...] (after build.sh VARIANT). Logs go to build/<variant>/logs.
T=${0:A:h}; BD=$T/build; v=${1:-head}; shift 2>/dev/null
mkdir -p $BD/$v/logs
TLS_SERVER=$BD/tls_server PKI=$BD/pki LOGDIR=$BD/$v/logs PORTBASE=${PORTBASE:-23000} ASAN_OPTIONS=detect_leaks=0:symbolize=0 $BD/$v/engine_test "$@"
