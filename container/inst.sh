#!/bin/bash

export package="${PACKAGE}"
export python_bin="${PYTHON_BIN}"
export output_file="${OUTPUT_FILE}"

export PYTHONUSERBASE=/home/developer
export XDG_CACHE_HOME=/home/developer/c

echo "Installing $package with $python_bin" 

if [ "$package" == "none" ] ; then
	echo "You need to specify a package to check."
fi

${python_bin} -m pip install --user "$package"

${python_bin} -m pip freeze --user 
${python_bin} -m pip freeze --user > "${output_file}"
bash


