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

import argparse
import timeout_decorator
import unittest
from util import *


class TestStressDR(unittest.TestCase):
    rule_ids = []
    @classmethod
    def tearDownClass(cls):
        subprocess.call(f"hdfs dfs -rm -r {HDFS_TEST_DIR}", shell=True)
        for rid in cls.rule_ids:
            delete_rule(rid)

    def test_sync_rule(self):
        file_paths = []
        cids = []

        # create a directory with random name
        source_dir = HDFS_TEST_DIR + random_string() + "/"

        rule_str = "file : path matches " + \
                   "\"" + source_dir + "*\" | sync -dest " + DEST_DIR
        rid = submit_rule(rule_str)
        start_rule(rid)

        # create random files in the above directory
        for i in range(MAX_NUMBER):
            file_path, cid = create_random_file_parallel(FILE_SIZE, source_dir)
            file_paths.append(file_path)
            cids.append(cid)
        wait_for_cmdlets(cids)


        # Status check
        while True:
            time.sleep(1)
            rule = get_rule(rid)
            if rule['numCmdsGen'] >= MAX_NUMBER:
                break
        cids = get_cids_of_rule(rid)
        failed = wait_for_cmdlets(cids)
        self.assertTrue(len(failed) == 0)
        time.sleep(5)
        stop_rule(rid)
        self.rule_ids.append(rid)


if __name__ == '__main__':
    requests.adapters.DEFAULT_RETRIES = 5
    s = requests.session()
    s.keep_alive = False

    parser = argparse.ArgumentParser()
    parser.add_argument('-size', default='1MB',
                        help="size of file, Default Value 1MB.")
    parser.add_argument('-num', default='10000',
                        help="file num, Default Value 10000.")
    # To sync files to another cluster, please use "-dest hdfs://hostname:port/dest/"
    parser.add_argument('-dest', default='/dest/',
                        help="directory to store generated test set, DefaultValue: /dest/")
    parser.add_argument('unittest_args', nargs='*')
    args, unknown_args = parser.parse_known_args()
    sys.argv[1:] = unknown_args
    print("The file size for test is {}.".format(args.size))
    FILE_SIZE = convert_to_byte(args.size)
    print("The file number for test is {}.".format(args.num))
    MAX_NUMBER = int(args.num)
    print("The dest directory for test is {}.".format(args.dest))
    DEST_DIR = args.dest

    unittest.main()
