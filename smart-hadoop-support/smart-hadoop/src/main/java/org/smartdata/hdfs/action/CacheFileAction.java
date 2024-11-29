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

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.protocol.CacheDirectiveInfo;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.scheduler.CacheScheduler;

import java.util.Map;
import java.util.Optional;

/**
 * Move to Cache Action
 */
@ActionSignature(
    actionId = "cache",
    displayName = "cache",
    usage = HdfsAction.FILE_PATH + " $file "
        + CacheFileAction.REPLICA + " $replica "
)
public class CacheFileAction extends HdfsAction {
  public static final String REPLICA = "-replica";

  private Path filePath;
  private short replication;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);

    filePath = getPathArg(FILE_PATH);
    replication = Optional.ofNullable(args.get(REPLICA))
        .map(Short::parseShort)
        .orElse((short) 0);
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArg(FILE_PATH);

    // set cache replication as the replication number of the file if not set
    if (replication == 0) {
      FileStatus fileStatus = localFileSystem.getFileStatus(filePath);
      replication = fileStatus.isDirectory() ? 1 : fileStatus.getReplication();
    }
    executeCacheAction();
  }

  boolean isFileCached() throws Exception {
    CacheDirectiveInfo filter = new CacheDirectiveInfo.Builder()
        .setPath(filePath)
        .build();
    return localFileSystem.listCacheDirectives(filter).hasNext();
  }

  private void executeCacheAction() throws Exception {
    if (isFileCached()) {
      this.appendLog("The given file has already been cached, " +
          "so there is no need to execute this action.");
      return;
    }

    addDirective();
  }

  private void addDirective() throws Exception {
    CacheDirectiveInfo filter = new CacheDirectiveInfo.Builder()
        .setPath(filePath)
        .setPool(CacheScheduler.SSM_POOL)
        .setReplication(replication)
        .build();

    localFileSystem.addCacheDirective(filter);
  }
}
