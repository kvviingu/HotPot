#!/bin/sh
# Old entry point, kept so existing commands still work. Everything now lives in hotpot.py:
#   ./deploy.sh check | front | backend | all | persona | dashboard | status | ssh-front | ssh-backend
case "${1:-}" in
  front | backend) set -- deploy "$1" ;;
  all) set -- deploy all ;;
  dashboard) set -- dashboard --config-only ;;
  ssh-front | ssh-backend) vm=${1#ssh-}; shift; set -- ssh "$vm" "$@" ;;
esac
exec "$(dirname "$0")/hotpot" "$@"
