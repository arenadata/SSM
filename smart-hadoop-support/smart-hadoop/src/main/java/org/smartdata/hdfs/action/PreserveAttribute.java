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
import org.apache.hadoop.fs.permission.FsPermission;
import org.smartdata.model.FileInfoDiff;

import java.util.Arrays;
import java.util.Optional;

public enum PreserveAttribute {
  OWNER("owner") {
    @Override
    public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
      String owner = Optional.ofNullable(srcFileStatus)
          .map(FileStatus::getOwner)
          .orElse(null);
      fileInfoDiff.setOwner(owner);
    }
  },
  GROUP("group") {
    @Override
    public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
      String group = Optional.ofNullable(srcFileStatus)
          .map(FileStatus::getGroup)
          .orElse(null);
      fileInfoDiff.setGroup(group);
    }
  },
  PERMISSIONS("permissions") {
    @Override
    public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
      Short permission = Optional.ofNullable(srcFileStatus)
          .map(FileStatus::getPermission)
          .map(FsPermission::toShort)
          .orElse(null);
      fileInfoDiff.setPermission(permission);
    }
  },
  REPLICATION_NUMBER("replication") {
    @Override
    public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
      Short blockReplication = Optional.ofNullable(srcFileStatus)
          .map(FileStatus::getReplication)
          .orElse(null);
      fileInfoDiff.setBlockReplication(blockReplication);
    }
  },
  MODIFICATION_TIME("modification-time") {
    @Override
    public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
      Long modificationTime = Optional.ofNullable(srcFileStatus)
          .map(FileStatus::getModificationTime)
          .orElse(null);
      fileInfoDiff.setModificationTime(modificationTime);
    }
  };

  private final String name;

  PreserveAttribute(String name) {
    this.name = name;
  }

  /**
   * Applies this attribute of the source file status to the file info diff.
   * If the source file status is null, the corresponding diff field is reset,
   * so that the attribute is left unchanged on the destination file.
   */
  public abstract void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus);

  @Override
  public String toString() {
    return name;
  }

  public static boolean isValidOption(String option) {
    return Arrays.stream(PreserveAttribute.values())
        .anyMatch(attr -> attr.toString().equalsIgnoreCase(option));
  }

  protected static PreserveAttribute fromOption(String option) {
    return Arrays.stream(PreserveAttribute.values())
        .filter(attr -> attr.toString().equalsIgnoreCase(option))
        .findFirst()
        .orElseThrow(() ->
            new IllegalArgumentException("Wrong preserve attribute: " + option));
  }
}