#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# -*- coding: utf-8 -*-
"""
This script is used to generate and submit SSM compress rule.
"""
import sys
import os
import argparse
import re
from util import *
from ssm_generate_test_data import create_test_set


def run_compress_rule(compress_dir, debug):
    # Create compress rule
    rule_str = "file : path matches " + \
        "\"" + compress_dir + os.sep + "*\" | compress"
    if debug:
        print("DEBUG: **********Submitting Compress Rule**********")
    rid = submit_rule(rule_str)
    if debug:
        print("DEBUG: Rule with ID " + str(rid) + " submitted")

    # Activate rule
    start_rule(rid)
    if debug:
        print("DEBUG: Rule with ID " + str(rid) + " started")

    # Wait for submitting actions by rule
    cmdlets = get_cmdlets_of_rule(rid)
    count = 0
    while not cmdlets and count < 30:
        if debug:
            print("DEBUG: sleep 1s to wait for action submission")
        time.sleep(1)
        count += 1
        cmdlets = get_cmdlets_of_rule(rid)

    # Check if every action is DONE
    if cmdlets:
        if debug:
            print("DEBUG: get generated cmdlets of new submitted rule")
        cids = get_cids_of_rule(rid)
        failed = wait_for_cmdlets(cids)
        if len(failed) != 0:
            for cid in failed:
                print("Failed to execute the cmdlet: id = " + str(cid))
        print("All actions execute successfully")
    else:
        print("No cmdlet is generated")
    stop_rule(rid)
    return rid


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Auto-generate and submit compress rules.')
    parser.add_argument("-d", "--testDir", default=HDFS_TEST_DIR, dest="testDir",
                        help="target test set directory Prefix, Default Value: HDFS_TEST_DIR in util.py")
    parser.add_argument("-n", "--fileNum", default='5', dest="fileNum",
                        help="number of test files, string input, e.g. '10', Default Value: 5.")
    parser.add_argument("-s", "--fileSize", default='10MB', dest="fileSize",
                        help="size of each test file, e.g. 10MB, 10KB, default unit KB, Default Value 1KB.")
    parser.add_argument("--noGen", nargs='?', const=1, default=0, dest="notGenerate",
                        help="do not generate test set data flag.")
    parser.add_argument("--debug", nargs='?', const=1, default=0, dest="debug",
                        help="print debug info.")
    options = parser.parse_args()

    # Convert arguments
    try:
        DEBUG = options.debug
        file_num = options.fileNum
        notGen = options.notGenerate

        # Get test file size
        file_size_arg = re.match(r"(\d+)(\w{2}).*", options.fileSize)
        if file_size_arg:
            file_size = int(file_size_arg.group(1))
            sizeUnit = file_size_arg.group(2)
            if sizeUnit != "MB" and sizeUnit != "KB":
                print("Wrong Size Unit.")
                print("Usage: python test_compress_rule -h")
                sys.exit(1)
            if sizeUnit == "MB":
                file_size = file_size * 1024
        else:
            print("Wrong file size input, e.g. 1MB or 1KB")
            sys.exit(1)

        if options.testDir:
            if options.testDir[-1:len(options.testDir)] == '/':
                test_dir = options.testDir[:-1]
            else:
                test_dir = options.testDir
        else:
            raise SystemExit

        if DEBUG:
            print("DEBUG: file number: " + file_num + ", file size: " + str(file_size) + sizeUnit
                  + ", test files directory: " + test_dir)
    except (ValueError, SystemExit) as e:
        print("Usage: python test_compress_file_rule.py -h")
    except IndexError:
        pass

    if notGen:
        print("Please make sure there are files in the test data directory: "
              + test_dir + "/data_" + file_num)
    else:
        create_test_set([int(file_num)], file_size, test_dir, DEBUG)
    rid = run_compress_rule(test_dir + "/data_" + file_num, DEBUG)
    delete_rule(rid)
    subprocess.call(f"hdfs dfs -rm -r {test_dir}", shell=True)

