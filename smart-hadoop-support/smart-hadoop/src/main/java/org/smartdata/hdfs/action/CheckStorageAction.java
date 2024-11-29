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

import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.StorageType;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.util.Map;

/**
 * Check and return file blocks storage location.
 */
@ActionSignature(
    actionId = "checkstorage",
    displayName = "checkstorage",
    usage = HdfsAction.FILE_PATH + " $file "
)
public class CheckStorageAction extends HdfsActionWithRemoteClusterSupport {
  private Path filePath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    filePath = getPathArg(FILE_PATH);
  }

  @Override
  protected void preExecute() {
    validateNonEmptyArg(FILE_PATH);
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    FileStatus fileStatus = fileSystem.getFileStatus(filePath);
    if (fileStatus.isDirectory()) {
      appendResult("This is a directory which has no storage result!");
      return;
    }

    BlockLocation[] fileBlockLocations =
        fileSystem.getFileBlockLocations(filePath, 0, fileStatus.getLen());
    if (fileBlockLocations.length == 0) {
      appendResult("File '" + filePath + "' has no blocks.");
      return;
    }

    for (BlockLocation blockLocation : fileBlockLocations) {
      appendResult(buildBlockInfo(blockLocation));
    }
  }

  private String buildBlockInfo(BlockLocation blockLocation) throws IOException {
    StringBuilder blockInfo = new StringBuilder();

    String[] names = blockLocation.getNames();
    StorageType[] storageTypes = blockLocation.getStorageTypes();

    blockInfo.append("File offset = ")
        .append(blockLocation.getOffset())
        .append(", ")
        .append("Block locations = {");

    for (int i = 0; i < names.length; i++) {
      blockInfo.append(names[i])
          .append("[")
          .append(storageTypes[i])
          .append("]")
          .append(" ");
    }

    return blockInfo.toString();
  }

}