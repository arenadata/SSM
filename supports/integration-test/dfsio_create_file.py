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

from util import *


def create_file_DFSIO(num):
    """
    Please use this script in namenode
    Each time create 10K files (10K in io_data).
    Then, move these data to HDFS_TEST_DIR.
    """
    dfsio_cmd = "hadoop jar " + \
        "/usr/lib/hadoop-mapreduce/hadoop-mapreduce-client-jobclient-3.3.6-tests.jar TestDFSIO " + \
        "-write -nrFiles 10000 -fileSize 0KB"
    for i in range(num):
        subprocess.call(dfsio_cmd, shell=True)
        # subprocess.call("hdfs dfs -mv /benchmarks/TestDFSIO/io_control " +
        #                 HDFS_TEST_DIR + str(i) + "_control", shell=True)
        subprocess.call("hdfs dfs -mv /benchmarks/TestDFSIO/io_data " +
                        HDFS_TEST_DIR + str(i) + "_data", shell=True)


if __name__ == '__main__':
    num = 50
    try:
        num = int(sys.argv[1])
    except ValueError:
        print("Usage: python dfsio_create_file [num]")
    except IndexError:
        pass
    create_file_DFSIO(num)
