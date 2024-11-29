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

import java.util.Map;

/**
 * An action to delete a single file in dest
 * If dest doesn't contains "hdfs" prefix, then destination will be set to
 * current cluster, i.e., delete file in current cluster.
 * Note that destination should contains filename.
 */
@ActionSignature(
    actionId = "delete",
    displayName = "delete",
    usage = HdfsAction.FILE_PATH + " $file"
)

public class DeleteFileAction extends HdfsActionWithRemoteClusterSupport {
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
    boolean successfullyDeleted = fileSystem.delete(filePath, true);
    if (!successfullyDeleted && fileSystem.exists(filePath)) {
      throw new ActionException("File was not deleted: " + filePath);
    }

    appendLog("File successfully deleted: " + filePath);
  }
}


