from util import *


def create_file_DFSIO(num):
    """
    Please use this script in namenode
    Each time create 10K files (10K in io_data).
    Then, move these data to HDFS_TEST_DIR.
    """
    dfsio_cmd = "hadoop jar " + \
        "/usr/lib/hadoop-mapreduce/hadoop-mapreduce-client-jobclient-3.2.4-tests.jar TestDFSIO " + \
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
