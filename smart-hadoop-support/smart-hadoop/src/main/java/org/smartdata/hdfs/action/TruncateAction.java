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
import org.smartdata.action.annotation.ActionSignature;

import java.util.Map;
import java.util.Optional;

/**
 * action to truncate file
 */
@ActionSignature(
    actionId = "truncate",
    displayName = "truncate",
    usage = HdfsAction.FILE_PATH + " $src "
        + TruncateAction.LENGTH + " $length"
)
public class TruncateAction extends HdfsActionWithRemoteClusterSupport {
  public static final String LENGTH = "-length";

  private Path srcPath;
  private long length;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);

    this.srcPath = getPathArg(FILE_PATH);
    this.length = Optional.ofNullable(args.get(LENGTH))
        .map(Long::parseLong)
        .orElse(-1L);
  }

  @Override
  protected void preExecute() {
    validateNonEmptyArgs(FILE_PATH, LENGTH);

    if (length < 0) {
      throw new IllegalArgumentException("Length should be non negative number");
    }
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    long oldLength = fileSystem.getFileStatus(srcPath).getLen();

    if (length > oldLength) {
      throw new IllegalArgumentException("Length is illegal");
    }
    fileSystem.truncate(srcPath, length);
  }
}
