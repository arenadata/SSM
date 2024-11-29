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
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.util.Map;
import java.util.Random;

@ActionSignature(
    actionId = "append",
    displayName = "append",
    usage = HdfsAction.FILE_PATH + " $src" +
        AppendFileAction.LENGTH + " $length" +
        AppendFileAction.BUF_SIZE + " $size"
)
public class AppendFileAction extends HdfsActionWithRemoteClusterSupport {
  static final String BUF_SIZE = "-bufSize";
  static final String LENGTH = "-length";

  private static final int DEFAULT_BUFF_SIZE = 64 * 1024;
  private static final long DEFAULT_LENGTH = 1024L;


  private Path filePath;
  private long length;
  private int bufferSize;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.filePath = getPathArg(FILE_PATH);

    this.bufferSize = args.containsKey(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUFF_SIZE;

    this.length = args.containsKey(LENGTH)
        ? Long.parseLong(args.get(LENGTH))
        : DEFAULT_LENGTH;
  }

  @Override
  protected void preExecute() throws Exception {
    validateNonEmptyArg(FILE_PATH);
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    if (!fileSystem.exists(filePath)) {
      throw new ActionException("Append Action fails, file doesn't exist!");
    }
    appendLog(
        String.format("Append to %s", filePath));

    Random random = new Random();
    try (FSDataOutputStream os = fileSystem.append(filePath, bufferSize)) {
      long remaining = length;

      while (remaining > 0) {
        int toAppend = (int) Math.min(remaining, bufferSize);
        byte[] bytes = new byte[toAppend];
        random.nextBytes(bytes);
        os.write(bytes);
        remaining -= toAppend;
      }
    }
  }
}
