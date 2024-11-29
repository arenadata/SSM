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
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.smartdata.model.FileInfoDiff;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Optional;

public class UpdateFileMetadataSupport {
  private final PrintStream logOutput;

  public UpdateFileMetadataSupport(PrintStream logOutput) {
    this.logOutput = logOutput;
  }

  public void changeFileMetadata(FileSystem destFileSystem,
      FileInfoDiff fileInfoDiff) throws IOException {
    Path srcPath = new Path(fileInfoDiff.getPath());
    FileStatus srcFileStatus = destFileSystem.getFileStatus(srcPath);

    maybeChangeOwnerAndGroup(destFileSystem, fileInfoDiff, srcFileStatus);
    maybeChangeBlockReplication(destFileSystem, fileInfoDiff, srcFileStatus);
    maybeChangePermissions(destFileSystem, fileInfoDiff, srcFileStatus);
    maybeChangeTimes(destFileSystem, fileInfoDiff, srcFileStatus);
  }

  private void maybeChangeOwnerAndGroup(FileSystem destFileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {

    String owner = Optional.ofNullable(fileInfoDiff.getOwner())
        .orElseGet(srcFileStatus::getOwner);
    String group = Optional.ofNullable(fileInfoDiff.getGroup())
        .orElseGet(srcFileStatus::getGroup);

    if (!owner.equals(srcFileStatus.getOwner())
        || !group.equals(srcFileStatus.getGroup())) {
      logOutput.printf("Updating file's owner from '%s' to '%s' " +
              "and file's group from '%s' to '%s'%n",
          srcFileStatus.getOwner(), owner,
          srcFileStatus.getGroup(), group);

      try {
        destFileSystem.setOwner(srcFileStatus.getPath(), owner, group);
      } catch (IOException e) {
        logOutput.println("Error changing owner and group: " + e.getMessage());
      }
    }
  }

  private void maybeChangeBlockReplication(FileSystem destFileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {

    Short newBlockReplication = fileInfoDiff.getBlockReplication();
    if (newBlockReplication != null
        && !newBlockReplication.equals(srcFileStatus.getReplication())) {
      logOutput.printf("Updating file's replication factor from '%s' to '%s'%n",
          srcFileStatus.getReplication(), newBlockReplication);

      try {
        destFileSystem.setReplication(srcFileStatus.getPath(), newBlockReplication);
      } catch (IOException e) {
        logOutput.println("Error changing replication: " + e.getMessage());
      }
    }
  }

  private void maybeChangePermissions(FileSystem destFileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {

    Short newPermission = fileInfoDiff.getPermission();
    if (newPermission != null
        && !newPermission.equals(srcFileStatus.getPermission().toShort())) {
      logOutput.printf("Updating file's permissions from '%s' to '%s'%n",
          srcFileStatus.getPermission().toShort(), newPermission);

      try {
        destFileSystem.setPermission(srcFileStatus.getPath(), new FsPermission(newPermission));
      } catch (IOException e) {
        logOutput.println("Error changing permissions: " + e.getMessage());
      }
    }
  }

  private void maybeChangeTimes(FileSystem destFileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {

    long modificationTime = Optional.ofNullable(fileInfoDiff.getModificationTime())
        .orElseGet(srcFileStatus::getModificationTime);
    long accessTime = Optional.ofNullable(fileInfoDiff.getAccessTime())
        .orElseGet(srcFileStatus::getAccessTime);

    if (accessTime != srcFileStatus.getAccessTime()
        || modificationTime != srcFileStatus.getModificationTime()) {
      logOutput.printf("Updating file's access time from '%s' to '%s' " +
              "and file's modification time from '%s' to '%s'%n",
          srcFileStatus.getAccessTime(), accessTime,
          srcFileStatus.getModificationTime(), modificationTime);

      try {
        destFileSystem.setTimes(srcFileStatus.getPath(), modificationTime, accessTime);
      } catch (IOException e) {
        logOutput.println("Error changing times: " + e.getMessage());
      }
    }
  }
}
