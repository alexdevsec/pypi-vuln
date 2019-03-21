import subprocess
import os
import tempfile
import time
import json
import gspread
import sys
from oauth2client.service_account import ServiceAccountCredentials
from subprocess import PIPE
from pathlib import Path



config = {
     # The location of some binaries
     'safety_bin': '~/local/bin/safety',
     'docker_bin': "/usr/bin/docker",

     # This is the version of python that we're running on the target.
     # Notice that this is the path of WITHIN THE CONTAINER. Not on the host. Got it?
     'python_bin' : "/usr/bin/python2.7",
     'python_bin_name' : "python2.7",

     # This is a cache for pypi packages. You'll want to set this and 
     # be consistent so it doesn't download everything over and over again.
     'package_cache_dir' : "./cache",

     # Where to put temporary results
     'results_dir_base' : "./results",

     # Google sheets configs
     'sheet_name' : 'Pypi vulnerabilities',
     'cred_file' : 'sheets_creds.json'
}

# 'verify_packages_file' : "test-list",

docker_image_name="pypi-vuln-scan"


next_row=0

def setup_sheets(sheet_name):
    global config,next_row
    scope = ['https://spreadsheets.google.com/feeds',
        'https://www.googleapis.com/auth/drive']

    try:
        credentials = ServiceAccountCredentials.from_json_keyfile_name(config['cred_file'], scope)
    except:
        print("Could not access service account")
        return False

    gc = gspread.authorize(credentials)

    worksheet = gc.open(sheet_name).sheet1
    next_row = next_available_row(worksheet)

    print("Next available row: "+str(next_row))
    return worksheet


def next_available_row(worksheet):
    str_list = list(filter(None, worksheet.col_values(1)))
    return len(str_list)+1

def find_version(package,requires_list):
    to_match=package+"=="
    try:
        matches=list(filter(lambda x: to_match in x, requires_list))
        version=(matches[0].split('=='))[1]
    except:
        version="version not found"
    return version


def find_dependencies(package,insert_if_already_run, python_bin, subdir_name):
    print("    Finding dependencies for "+package)
    # Check to make sure output directory exists
    results_dir=Path(config['results_dir_base']+'/'+subdir_name)
    results_file=results_dir / ("pypi-vuln-"+package)
    cache_dir=Path(config['package_cache_dir'])

    # Only run the container if there's no existing log

    if (not insert_if_already_run) and Path(results_file).is_file():
        return {}

    if not Path(results_file).is_file():

        # This is relative to the container
        output_file="/install-results/pypi-vuln-"+package

        env=dict(os.environ,PACKAGE=package)
        docker_commands = [config['docker_bin'],"run","--rm","-e","PACKAGE="+package,
            "-e","PYTHON_BIN="+config['python_bin'],
            "-e","OUTPUT_FILE="+output_file,
            "--mount",'type=bind,source='+str(results_dir.absolute())+',target=/install-results',
            "--mount",'type=bind,source='+str(cache_dir.absolute())+',target=/home/developer/c',
            docker_image_name]

        output=subprocess.check_output(docker_commands,env=env,shell=False)

    try: 
        requires_list = open(results_file).read().splitlines()
    except:
        print("Couldn't get requires list. Dependency check was: "+output.decode('ascii'))
        requires_list = []

    return requires_list


def process_requires_list(requires_list):
 
    input_file=tempfile.NamedTemporaryFile(mode='w',delete=False)
    input_file.write("\n".join(requires_list))
    input_file.close()

    safety_commands=[safety_bin,"check","-r",input_file.name,"--json"]

    sb=subprocess.run(safety_commands, stdout=PIPE, stderr=PIPE)
    output=sb.stdout.decode('ascii')

    return output

def add_problem(worksheet,package_count,package_name,package_version,json_text):
    global next_row
    package_problem=json.loads(json_text)
    number_of_problems = len(package_problem)
    if number_of_problems == 0:
        print("    No problem added for "+package_name+ " version "+package_version)
        return

    print("    Adding "+str(number_of_problems)+" problems for "+package_name+ " version "+package_version)

    for p in package_problem:
        required_package_name=p[0]
        rule=p[1]
        required_package_version=p[2]
        description=p[3]
        safety_id=p[4]
        print("    Package name: "+required_package_name+" version: "+required_package_version)

        cell_range_description = "A%d:H%d" % (next_row,next_row)
        cell_list = worksheet.range(cell_range_description)

        cell_values = [ package_name, package_version, required_package_name, 
            required_package_version, rule, safety_id, description,package_count]

        for i, val in enumerate(cell_values):
            cell_list[i].value = val

        worksheet.update_cells(cell_list)
        next_row = next_row + 1

    return True


def main():

    global config

    package_count=0

    if len(sys.argv) != 2:
        print("Need to specify the list of packages.")
        return 1

    verify_packages_file=sys.argv[1]

    print("Verifying Pypi...")

    try:
        input_packages = open(verify_packages_file,"r")
    except:
        print("Could not access package list file "+verify_packages_file)
        return 1

    print("Creds file: "+config['cred_file'])
    worksheet = setup_sheets(config['sheet_name'])

    if worksheet == False:
        print("Could not setup sheets")
        return 1

    insert_if_already_run=True


    for package in input_packages:
        package_count=package_count+1
        package=package.rstrip()
        print("Package "+str(package_count)+": "+package)

        requires_list=find_dependencies(package,insert_if_already_run,config['python_bin'],config['python_bin_name'])

        if requires_list == {}:
            print("    Already processed")
            continue
        if not insert_if_already_run:
            print("    Already loaded, won't add")
            continue
        if len(requires_list)==0:
            continue
        package_version = find_version(package,requires_list)
        problem_json=process_requires_list(requires_list)
        add_problem(worksheet, package_count,package,package_version,problem_json)


if __name__ == "__main__":
    main()


