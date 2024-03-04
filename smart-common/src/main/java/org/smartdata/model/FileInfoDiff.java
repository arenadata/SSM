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

package org.smartdata.model;

import java.util.Objects;

public class FileInfoDiff {
  private String path;
  private Long length;
  private Short blockReplication;
  private Long modificationTime;
  private Long accessTime;
  private Short permission;
  private String owner;
  private String group;
  private Byte erasureCodingPolicy;

  public String getPath() {
    return path;
  }

  public FileInfoDiff setPath(String path) {
    this.path = path;
    return this;
  }

  public Long getLength() {
    return length;
  }

  public FileInfoDiff setLength(Long length) {
    this.length = length;
    return this;
  }

  public Short getBlockReplication() {
    return blockReplication;
  }

  public FileInfoDiff setBlockReplication(Short blockReplication) {
    this.blockReplication = blockReplication;
    return this;
  }

  public Long getModificationTime() {
    return modificationTime;
  }

  public FileInfoDiff setModificationTime(Long modificationTime) {
    this.modificationTime = modificationTime;
    return this;
  }

  public Long getAccessTime() {
    return accessTime;
  }

  public FileInfoDiff setAccessTime(Long accessTime) {
    this.accessTime = accessTime;
    return this;
  }

  public Short getPermission() {
    return permission;
  }

  public FileInfoDiff setPermission(Short permission) {
    this.permission = permission;
    return this;
  }

  public String getOwner() {
    return owner;
  }

  public FileInfoDiff setOwner(String owner) {
    this.owner = owner;
    return this;
  }

  public String getGroup() {
    return group;
  }

  public FileInfoDiff setGroup(String group) {
    this.group = group;
    return this;
  }

  public Byte getErasureCodingPolicy() {
    return erasureCodingPolicy;
  }

  public FileInfoDiff setErasureCodingPolicy(Byte erasureCodingPolicy) {
    this.erasureCodingPolicy = erasureCodingPolicy;
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FileInfoDiff that = (FileInfoDiff) o;
    return Objects.equals(path, that.path)
        && Objects.equals(length, that.length)
        && Objects.equals(blockReplication, that.blockReplication)
        && Objects.equals(modificationTime, that.modificationTime)
        && Objects.equals(accessTime, that.accessTime)
        && Objects.equals(permission, that.permission)
        && Objects.equals(owner, that.owner)
        && Objects.equals(group, that.group)
        && Objects.equals(erasureCodingPolicy, that.erasureCodingPolicy);
  }

  @Override
  public int hashCode() {
    return Objects.hash(path, length, blockReplication,
        modificationTime, accessTime, permission, owner, group, erasureCodingPolicy);
  }

  @Override
  public String toString() {
    return "FileInfoDiff{"
        + "path='" + path + '\''
        + ", length=" + length
        + ", blockReplication=" + blockReplication
        + ", modificationTime=" + modificationTime
        + ", accessTime=" + accessTime
        + ", permission=" + permission
        + ", owner='" + owner + '\''
        + ", group='" + group + '\''
        + ", erasureCodingPolicy=" + erasureCodingPolicy
        + '}';
  }
}
