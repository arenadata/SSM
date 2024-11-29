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

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.io.InputStream;
import java.util.Map;

/**
 * An action to read a file. The read content will be discarded immediately, not storing onto disk.
 * Can be used to test: 1. cache file; 2. one-ssd/all-ssd file;
 *
 * <p>Arguments: file_path [buffer_size, default=64k]
 */
@ActionSignature(
    actionId = "read",
    displayName = "read",
    usage = HdfsAction.FILE_PATH + " $file "
        + ReadFileAction.BUF_SIZE + " $size"
)
public class ReadFileAction extends HdfsActionWithRemoteClusterSupport {
  public static final String BUF_SIZE = "-bufSize";
  public static final int DEFAULT_BUFFER_SIZE = 64 * 1024;

  private Path filePath;
  private int bufferSize;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.filePath = getPathArg(FILE_PATH);
    this.bufferSize = args.containsKey(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUFFER_SIZE;
  }

  @Override
  protected void preExecute() {
    validateNonEmptyArg(FILE_PATH);
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    if (!fileSystem.exists(filePath)) {
      throw new ActionException("ReadFile Action fails, file " +
          filePath + " doesn't exist!");
    }

    byte[] buffer = new byte[bufferSize];
    try (InputStream inputStream = fileSystem.open(filePath)) {
      while (inputStream.read(buffer, 0, bufferSize) != -1) {
      }
    }
  }
}
