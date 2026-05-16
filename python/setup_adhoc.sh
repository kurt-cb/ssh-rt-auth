#!/bin/bash

. ../.venv/bin/activate

# Setting up tests
pytest tests/lxc/test_setup_only.py -v -m setup_only
RC=$?

if [ "$RC" != "0" ]; then
   echo "Environment failed to generate"
   exit 1
fi
# shell out
echo Shell-ing out with addhoc-env setup, ADHOC_TEST_ENV.md has details of environment
bash -x -c 'source ./adhoc-env.sh; PS1="adhoc> "; exec bash'
cleanup_containers.sh
rm ADHOC_TEST_ENV.md
rm adhoc-env.sh
exit 0
