from multiprocessing.pool import Pool
from subprocess import check_output
import argparse
from copy import deepcopy

import pyarrow as pa
import pyarrow.fs

from util import *


os.environ['CLASSPATH'] = str(check_output([f"{os.environ['HADOOP_HOME']}/bin/hadoop", "classpath", "--glob"]))


def create_file_pyarrow(file_batch):
    fs = pa.fs.HadoopFileSystem(host=HOST, user=USER)
    print(f"Start processing {len(file_batch)} files")

    for file_index, file in enumerate(file_batch):
        with fs.open_output_stream(file) as stream:

            batch_write = int(SIZE // BATCH_SIZE) > 2
            batch_size = BATCH_SIZE if batch_write else SIZE
            write_bytes = b''.join([b'a' for _ in range(batch_size)])

            if batch_write:
                current_size = deepcopy(SIZE)

                while current_size > batch_size:
                    stream.write(write_bytes)
                    current_size -= batch_size

                if current_size != 0:
                    write_bytes = b''.join([b'a' for _ in range(current_size)])
                    stream.write(write_bytes)

            else:
                stream.write(write_bytes)


def main(num, num_proc, human_size):

    files = [HDFS_TEST_DIR + random_string() for _ in range(num)]

    if num_proc >= len(files):
        chunk_size = 1
    else:
        chunk_size = (len(files) // num_proc)
    chunks = [
        files[i:i+chunk_size]
        for i in range(0, len(files), chunk_size)
    ]

    stime = time.time()
    p = Pool(num_proc)
    p.map(create_file_pyarrow, chunks)
    etime = time.time()
    print("creating files")
    print("create %d * %s files in %fs" % (len(files), human_size, etime - stime))


if __name__ == '__main__':
    # Parse arguments
    default_proc = cpu_count()
    parser = argparse.ArgumentParser(description='Generate test data set for HDFS.')
    parser.add_argument("-d", "--dir", default=HDFS_TEST_DIR, dest="dir",
                        help="directory for files")
    parser.add_argument("-n", "--num", default=1000, dest="num",
                        help="Num files.")
    parser.add_argument("-s", "--size", default='1MB', dest="size",
                        help="size of each file, e.g. 10MB, 10KB, Default Value 1MB.")
    parser.add_argument("-b", "--batch-size", dest="batch_size", default="1MB",
                        help="Batch size for write file e.g. GB, MB, KB, Default Value 1MB.")
    parser.add_argument("--host", dest="host",
                        help="HDFS host NameNode")
    parser.add_argument("-u", "--user", dest="user", default="ssm",
                        help="User. Default - ssm")
    parser.add_argument("-p", "--proc", dest="proc", default=default_proc,
                        help="Processes count. default = cpu  ")

    options = parser.parse_args()
    HOST = options.host
    USER = options.user
    SIZE = convert_to_byte(options.size)
    BATCH_SIZE = convert_to_byte(options.batch_size)

    main(int(options.num), int(options.proc), options.size)
