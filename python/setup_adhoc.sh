#!/bin/bash

. .venv/bin/activate

# Setting up tests
pytest tests/lxc/test_setup_only.py -v -m setup_only

# shell out
echo Shell-ing out with addhoc-env setup, ADHOC_TEST_ENV.md has details of environment
bash -i adhoc-env.sh
cleanup_containers.sh
rm ADHOC_TEST_ENV.md
rm adhoc-env.sh
exit 0
