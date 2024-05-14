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
import unittest
from util import *

# In smart-default, smart.rule.executors confines the parallelism for SSM rules.
# To make stress test for rules, this property's value should be set large enough.


class TestStressRule(unittest.TestCase):
    rids = []
    @classmethod
    def tearDownClass(cls):
        subprocess.call(f"hdfs dfs -rm -r {HDFS_TEST_DIR}", shell=True)

        for rid in cls.rids:
            delete_rule(rid)

    def test_rule(self):
        rids = []
        for i in range(MAX_NUMBER):
            rule_str = "file: " + \
                "every 4s from now to now + 1d |" + \
                " path matches " + \
                "\"/ssmtest/" + random_string()[:5] + " *\"" + \
                " | onessd "
            rids.append(submit_rule(rule_str))
        # activate all rules
        for rid in rids:
            start_rule(rid)
            self.rids.append(rid)
        # sleep 60s
        time.sleep(60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-num', default='100',
                        help="file num, Default Value 100.")
    parser.add_argument('unittest_args', nargs='*')
    args, unknown_args = parser.parse_known_args()
    sys.argv[1:] = unknown_args
    print("A reminder: the value for smart.rule.executors in smart-default.xml" \
          " should be set large enough.")
    print("The rule number for test is {}.".format(args.num))
    MAX_NUMBER = int(args.num)

    unittest.main()
