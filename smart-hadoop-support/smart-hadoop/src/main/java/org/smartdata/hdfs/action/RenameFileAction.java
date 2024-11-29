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

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.utils.PathUtil.getScheme;

/**
 * An action to rename a single file
 * If dest doesn't contains "hdfs" prefix, then destination will be set to
 * current cluster.
 * Note that destination should contains filename.
 */
@ActionSignature(
    actionId = "rename",
    displayName = "rename",
    usage = HdfsAction.FILE_PATH + " $src " + RenameFileAction.DEST_PATH +
        " $dest"
)
public class RenameFileAction extends HdfsActionWithRemoteClusterSupport {
  public static final String DEST_PATH = "-dest";

  private Path srcPath;
  private Path destPath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.destPath = getPathArg(DEST_PATH);
  }

  @Override
  protected boolean isRemoteMode() {
    return getScheme(srcPath).isPresent() || getScheme(destPath).isPresent();
  }

  @Override
  protected void preExecute() {
    validateNonEmptyArgs(FILE_PATH, DEST_PATH);
  }

  @Override
  protected void preRemoteExecute() throws Exception {
    Optional<String> srcScheme = getScheme(srcPath);
    Optional<String> destScheme = getScheme(destPath);

    // One of files is in local cluster and second is in remote
    // TODO handle the case when absolute path's host is local cluster
    if (!srcScheme.isPresent() || !destScheme.isPresent()) {
      throw new ActionException("Paths are not in the same cluster");
    }

    if (!srcScheme.get().equals(destScheme.get())) {
      throw new ActionException("Paths have different schemes");
    }

    if (!destPath.toUri().getHost().equals(srcPath.toUri().getHost())) {
      throw new ActionException("Paths are not in the same cluster");
    }
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    if (!fileSystem.rename(srcPath, destPath)) {
      throw new IOException("Failed to rename " + srcPath + " to " + destPath);
    }
  }

  @Override
  protected void postExecute() {
    appendLog("File " + srcPath + " was renamed to " + destPath);
  }
}
