/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.hdfs.file.equality;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileChecksum;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.model.FileInfo;

import java.io.IOException;
import java.util.Optional;

import static org.smartdata.utils.PathUtil.getRemoteFileSystem;
import static org.smartdata.utils.PathUtil.isAbsoluteRemotePath;

public class ChecksumFileEqualityStrategy implements FileEqualityStrategy {
  static final Logger LOG = LoggerFactory.getLogger(ChecksumFileEqualityStrategy.class);

  private final LengthFileEqualityStrategy filesLengthComparator
      = new LengthFileEqualityStrategy();

  private final Configuration config;

  public ChecksumFileEqualityStrategy(Configuration config) {
    this.config = config;
  }

  private FileSystem getFileSystem(Path path, Configuration conf) throws IOException {
    return isAbsoluteRemotePath(path)
        ? getRemoteFileSystem(path, conf)
        : FileSystem.get(HadoopUtil.getNameNodeUri(conf), conf);
  }

  @Override
  public boolean areEqual(FileInfo srcFileInfo, FileStatus destFileStatus) {
    if (!filesLengthComparator.areEqual(srcFileInfo, destFileStatus)) {
      // we don't need to fetch and compare checksums
      // if the files are obviously not equal.
      return false;
    }
    Path srcPath = new Path(srcFileInfo.getPath());
    Path destPath = destFileStatus.getPath();

    try {
      FileChecksum srcChecksum = getFileSystem(srcPath, config)
          .getFileChecksum(srcPath);
      FileChecksum destChecksum = getFileSystem(destPath, config)
          .getFileChecksum(destPath);

      return Optional.ofNullable(srcChecksum)
          .filter(checksum -> checksum.equals(destChecksum))
          .isPresent();
    } catch (IOException exception) {
      LOG.error("Error comparing checksums of files '{}' and '{}'",
          srcPath, destPath, exception);
      return false;
    }
  }
}
