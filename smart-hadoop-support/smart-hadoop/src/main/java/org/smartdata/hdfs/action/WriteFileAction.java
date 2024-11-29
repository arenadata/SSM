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
package org.smartdata.hdfs.action;

import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.annotation.ActionSignature;

import java.util.Map;
import java.util.Optional;
import java.util.Random;

/**
 * An action to write a file with generated content. Can be used to test: 1. storage policy; 2.
 * stripping erasure coded file; 3. small file.
 *
 * <p>Arguments: file_path length [buffer_size, default=64k]
 */
@ActionSignature(
    actionId = "write",
    displayName = "write",
    usage =
        HdfsAction.FILE_PATH
            + " $file "
            + WriteFileAction.LENGTH
            + " $length "
            + WriteFileAction.BUF_SIZE
            + " $size"
)
public class WriteFileAction extends HdfsActionWithRemoteClusterSupport {
  public static final String LENGTH = "-length";
  public static final String BUF_SIZE = "-bufSize";

  public static final long DEFAULT_LENGTH = 1024;
  public static final int DEFAULT_BUF_SIZE = 64 * 1024;

  private Path filePath;
  private long length;
  private int bufferSize;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.filePath = getPathArg(FILE_PATH);
    this.length = Optional.ofNullable(args.get(LENGTH))
        .map(Long::parseLong)
        .orElse(DEFAULT_LENGTH);

    this.bufferSize = Optional.ofNullable(args.get(BUF_SIZE))
        .map(Integer::parseInt)
        .orElse(DEFAULT_BUF_SIZE);
  }

  @Override
  protected void preExecute() throws Exception {
    validateNonEmptyArg(FILE_PATH);

    if (length == -1) {
      throw new IllegalArgumentException("Write Action provides wrong length! ");
    }
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    short replication = fileSystem.getServerDefaults(filePath).getReplication();

    try (FSDataOutputStream out = fileSystem.create(filePath, replication)) {
      // generate random data with given length
      byte[] buffer = new byte[bufferSize];
      new Random().nextBytes(buffer);

      appendLog("Generate random data with length: " + length);
      for (long pos = 0; pos < length; pos += bufferSize) {
        long writeLength = pos + bufferSize < length ? bufferSize : length - pos;
        out.write(buffer, 0, (int) writeLength);
      }
    }

    appendLog("Write Successfully!");
  }
}
