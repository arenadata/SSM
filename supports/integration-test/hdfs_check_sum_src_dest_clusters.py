import argparse
import hdfs


class HdfsPath:
    def __init__(self, client: hdfs.Client, path: str):
        self.client = client
        self.path = path

    def __eq__(self, other):
        eq = True
        if self.client.status(self.path)["type"] == "FILE":
            try:
                eq = (self.client.checksum(self.path) == other.client.checksum(self.path))
                return eq
            except hdfs.util.HdfsError:
                eq = False
                print(f"not equivalent {self.path}")
                return eq
        else:
            files = self.client.list(self.path)
            num_files = len(files)
            print(f"Checking {num_files} files")
            for i, file in enumerate(files, 1):
                check_path = f"{self.path}{file}"
                hdfs_path = HdfsPath(self.client, check_path)
                eq = (hdfs_path == other)
                if not eq:
                    print(f"not equivalent {check_path}")
                    return eq
                if i % 100 == 0:
                    print(f"success check {i}/{num_files} files")
        return eq


def check_sum_src_dest_clusters(src_url: str, dest_url: str, path: str):
    src_hdfs_client = hdfs.Client(url=src_url)
    dest_hdfs_client = hdfs.Client(url=dest_url)

    src_hdfs_path = HdfsPath(src_hdfs_client, path)
    dest_hdfs_path = HdfsPath(dest_hdfs_client, path)
    print(f"Checking hash sum for path `{path}`")
    result = (src_hdfs_path == dest_hdfs_path)
    print(f"The hashes of files along path `{path}` are equivalent - {result}")


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Generate test data set for HDFS.')
    parser.add_argument("-s", "--src", dest="src_url",
                        help="src web hdfs url - http:<hostname|ip>:<port>")
    parser.add_argument("-d", "--dest", dest="dest_url",
                        help="dest web hdfs url - http:<hostname|ip>:<port>")
    parser.add_argument("-p", "--path", dest="path",
                        help="Path /<dir_path>/ or /../<file_path>")
    options = parser.parse_args()
    src_url = options.src_url
    dest_url = options.dest_url
    path = options.path

    check_sum_src_dest_clusters(src_url, dest_url, path)
