/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.hdfs.action;

import static org.smartdata.utils.ConfigUtil.toRemoteClusterConfig;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.util.Optional;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.model.FileInfoDiff;

public class UpdateFileMetadataSupport {
  private final Configuration configuration;
  private final PrintStream logOutput;

  public UpdateFileMetadataSupport(Configuration configuration, PrintStream logOutput) {
    this.configuration = configuration;
    this.logOutput = logOutput;
  }

  public void changeFileMetadata(FileInfoDiff fileInfoDiff) throws IOException {
    if (fileInfoDiff.getPath().startsWith("hdfs")) {
      changeRemoteFileMetadata(fileInfoDiff);
    } else {
      changeLocalFileMetadata(fileInfoDiff);
    }
  }

  private void changeRemoteFileMetadata(FileInfoDiff fileInfoDiff) throws IOException {
    FileSystem remoteFileSystem = FileSystem.get(URI.create(fileInfoDiff.getPath()),
        toRemoteClusterConfig(configuration));
    changeFileMetadata(fileInfoDiff, remoteFileSystem);
  }

  private void changeLocalFileMetadata(FileInfoDiff fileInfoDiff) throws IOException {
    FileSystem localFileSystem = FileSystem.get(
        HadoopUtil.getNameNodeUri(configuration), configuration);
    changeFileMetadata(fileInfoDiff, localFileSystem);
  }

  private void maybeChangeOwnerAndGroup(FileSystem fileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) throws IOException {

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
      fileSystem.setOwner(srcFileStatus.getPath(), owner, group);
    }
  }

  private void maybeChangeBlockReplication(FileSystem fileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) throws IOException {

    Short newBlockReplication = fileInfoDiff.getBlockReplication();
    if (newBlockReplication != null
        && !newBlockReplication.equals(srcFileStatus.getReplication())) {
      logOutput.printf("Updating file's replication factor from '%s' to '%s'%n",
          srcFileStatus.getReplication(), newBlockReplication);
      fileSystem.setReplication(srcFileStatus.getPath(), newBlockReplication);
    }
  }

  private void maybeChangePermissions(FileSystem fileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) throws IOException {

    Short newPermission = fileInfoDiff.getPermission();
    if (newPermission != null
        && !newPermission.equals(srcFileStatus.getPermission().toShort())) {
      logOutput.printf("Updating file's permissions from '%s' to '%s'%n",
          srcFileStatus.getPermission().toShort(), newPermission);
      fileSystem.setPermission(srcFileStatus.getPath(), new FsPermission(newPermission));
    }
  }

  private void maybeChangeTimes(FileSystem fileSystem,
      FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) throws IOException {

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
      fileSystem.setTimes(srcFileStatus.getPath(), modificationTime, accessTime);
    }
  }

  private void changeFileMetadata(
      FileInfoDiff fileInfoDiff, FileSystem fileSystem) throws IOException {
    Path srcPath = new Path(fileInfoDiff.getPath());
    FileStatus srcFileStatus = fileSystem.getFileStatus(srcPath);

    maybeChangeOwnerAndGroup(fileSystem, fileInfoDiff, srcFileStatus);
    maybeChangeBlockReplication(fileSystem, fileInfoDiff, srcFileStatus);
    maybeChangePermissions(fileSystem, fileInfoDiff, srcFileStatus);
    maybeChangeTimes(fileSystem, fileInfoDiff, srcFileStatus);
  }
}
