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
package org.smartdata.test.step;

import io.arenadata.test.model.WaitParams;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.smartdata.test.model.SsmComponent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@Service
public class HdfsStep {
  private static final String HDFS_USER = "root";
  private static final String REPLACE_DATANODE_ON_FAILURE_KEY =
      "dfs.client.block.write.replace-datanode-on-failure.enable";
  private static final WaitParams SYNC_ACTION_TIMEOUT = DEFAULT_WAIT_PARAMS;

  @Value("${hdfs.source-fs-uri}")
  private String sourceFsUri;
  @Value("${hdfs.target-fs-uri}")
  private String targetFsUri;

  @Step("Create directory '{path}' on {component}")
  public HdfsStep createDirectory(SsmComponent component, String path) {
    withFileSystem(component, fileSystem -> fileSystem.mkdirs(new Path(path)));
    return this;
  }

  @Step("Create file '{path}' with content '{content}' on {component}")
  public HdfsStep createFile(SsmComponent component, String path, String content) {
    withFileSystem(component, fileSystem -> {
      try (OutputStream out = fileSystem.create(new Path(path), false)) {
        out.write(content.getBytes(StandardCharsets.UTF_8));
      }
      return null;
    });
    return this;
  }

  @Step("Append content '{content}' to file '{path}' on {component}")
  public HdfsStep appendToFile(SsmComponent component, String path, String content) {
    withFileSystem(component, fileSystem -> {
      try (OutputStream out = fileSystem.append(new Path(path))) {
        out.write(content.getBytes(StandardCharsets.UTF_8));
      }
      return null;
    });
    return this;
  }

  @Step("Delete '{path}' on {component}")
  public HdfsStep delete(SsmComponent component, String path) {
    withFileSystem(component, fileSystem -> fileSystem.delete(new Path(path), true));
    return this;
  }

  @Step("Rename '{srcPath}' to '{dstPath}' on {component}")
  public HdfsStep rename(SsmComponent component, String srcPath, String dstPath) {
    boolean renamed = withFileSystem(component, fileSystem ->
        fileSystem.rename(new Path(srcPath), new Path(dstPath)));
    assertThat(renamed)
        .as("Failed to rename '%s' to '%s' on %s", srcPath, dstPath, component)
        .isTrue();
    return this;
  }

  @Step("Set permissions '{permissions}' for '{path}' on {component}")
  public HdfsStep setPermissions(SsmComponent component, String path, String permissions) {
    withFileSystem(component, fileSystem -> {
      fileSystem.setPermission(new Path(path), new FsPermission(permissions));
      return null;
    });
    return this;
  }

  @Step("Set replication factor '{replication}' for '{path}' on {component}")
  public HdfsStep setReplication(SsmComponent component, String path, int replication) {
    withFileSystem(component, fileSystem ->
        fileSystem.setReplication(new Path(path), (short) replication));
    return this;
  }

  @Step("Check file or directory '{path}' exists on {component}")
  public boolean exists(SsmComponent component, String path) {
    return withFileSystem(component, fileSystem -> fileSystem.exists(new Path(path)));
  }

  @Step("Get content of file '{path}' on {component}")
  public String getFileContent(SsmComponent component, String path) {
    return withFileSystem(component, fileSystem -> {
      try (InputStream in = fileSystem.open(new Path(path));
           ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        byte[] buffer = new byte[4096];
        int read;
        while ((read = in.read(buffer)) != -1) {
          out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
      }
    });
  }

  @Step("Get permissions of '{path}' on {component}")
  public String getPermissions(SsmComponent component, String path) {
    short permissions = withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getPermission().toOctal());
    return String.valueOf(permissions);
  }

  @Step("Get replication factor of '{path}' on {component}")
  public String getReplication(SsmComponent component, String path) {
    short replication = withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getReplication());
    return String.valueOf(replication);
  }

  @Step("Get owner of '{path}' on {component}")
  public String getOwner(SsmComponent component, String path) {
    return withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getOwner());
  }

  @Step("Get group of '{path}' on {component}")
  public String getGroup(SsmComponent component, String path) {
    return withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getGroup());
  }

  @Step("Set owner '{owner}' and group '{group}' for '{path}' on {component}")
  public HdfsStep setOwner(SsmComponent component, String path, String owner, String group) {
    withFileSystem(component, fileSystem -> {
      fileSystem.setOwner(new Path(path), owner, group);
      return null;
    });
    return this;
  }

  @Step("Set modification time '{modificationTime}' for '{path}' on {component}")
  public HdfsStep setModificationTime(SsmComponent component, String path, long modificationTime) {
    withFileSystem(component, fileSystem -> {
      fileSystem.setTimes(new Path(path), modificationTime, -1);
      return null;
    });
    return this;
  }

  @Step("Get modification time of '{path}' on {component}")
  public long getModificationTime(SsmComponent component, String path) {
    return withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getModificationTime());
  }

  @Step("Check owner of '{path}' is '{expectedOwner}' and group is '{expectedGroup}' on {component}")
  public void checkOwner(SsmComponent component, String path, String expectedOwner, String expectedGroup) {
    try {
      FileStatus fileStatus = withFileSystem(component, fileSystem ->
          fileSystem.getFileStatus(new Path(path)));
      assertThat(fileStatus.getOwner())
          .as("Owner of file '%s' on %s", path, component)
          .isEqualTo(expectedOwner);
      assertThat(fileStatus.getGroup())
          .as("Group of file '%s' on %s", path, component)
          .isEqualTo(expectedGroup);
    } catch (UncheckedIOException e) {
      throw new AssertionError(
          format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
    }
  }

  @Step("Check modification time of '{path}' is {expectedModificationTime} on {component}")
  public void checkModificationTime(SsmComponent component, String path, long expectedModificationTime) {
    try {
      assertThat(getModificationTime(component, path))
          .as("Modification time of file '%s' on %s", path, component)
          .isEqualTo(expectedModificationTime);
    } catch (UncheckedIOException e) {
      throw new AssertionError(
          format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
    }
  }

  @Step("Check replication factor of '{path}' is '{expectedReplication}' on {component}")
  public void checkReplication(SsmComponent component, String path, String expectedReplication) {
    try {
      assertThat(getReplication(component, path))
          .as("Replication factor of file '%s' on %s", path, component)
          .isEqualTo(expectedReplication);
    } catch (UncheckedIOException e) {
      throw new AssertionError(
          format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
    }
  }

  @Step("Check file '{path}' exists on {component}")
  public void checkFileExists(SsmComponent component, String path) {
    assertThat(exists(component, path))
        .as("File '%s' should exist on %s", path, component)
        .isTrue();
  }

  @Step("Check file '{path}' does not exist on {component}")
  public void checkFileNotExists(SsmComponent component, String path) {
    assertThat(exists(component, path))
        .as("File '%s' should not exist on %s", path, component)
        .isFalse();
  }

  @Step("Check file '{path}' has content '{expectedContent}' on {component}")
  public void checkFileContent(SsmComponent component, String path, String expectedContent) {
    try {
      assertThat(getFileContent(component, path))
          .as("Content of file '%s' on %s", path, component)
          .isEqualTo(expectedContent);
    } catch (UncheckedIOException e) {
      throw new AssertionError(
          format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
    }
  }

  @Step("Check file '{path}' has permissions '{expectedPermissions}' on {component}")
  public void checkPermissions(SsmComponent component, String path, String expectedPermissions) {
    try {
      assertThat(getPermissions(component, path))
          .as("Permissions of file '%s' on %s", path, component)
          .isEqualTo(expectedPermissions);
    } catch (UncheckedIOException e) {
      throw new AssertionError(
          format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
    }
  }

  @Step("Create file '{path}' with content '{content}' on {component} and wait until it appears on {awaitComponent}")
  public HdfsStep createFileAndAwaitOn(SsmComponent component, String path, String content,
      SsmComponent awaitComponent) {
    createFile(component, path, content);
    waitUntilFileHasContent(awaitComponent, path, content);
    return this;
  }

  @Step("Create file '{path}' with content '{content}' on {firstComponent} and {secondComponent}")
  public HdfsStep createFileOnBothClusters(SsmComponent firstComponent, SsmComponent secondComponent,
      String path, String content) {
    createFile(firstComponent, path, content);
    createFile(secondComponent, path, content);
    return this;
  }

  @Step("Wait until file '{path}' has content '{expectedContent}' on {component}")
  public void waitUntilFileHasContent(SsmComponent component, String path, String expectedContent) {
    waitUntil(() -> checkFileContent(component, path, expectedContent), SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until file '{path}' does not exist on {component}")
  public void waitUntilFileNotExists(SsmComponent component, String path) {
    waitUntil(() -> checkFileNotExists(component, path), SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until file '{path}' has permissions '{expectedPermissions}' on {component}")
  public void waitUntilFileHasPermissions(SsmComponent component, String path, String expectedPermissions) {
    waitUntil(() -> checkPermissions(component, path, expectedPermissions), SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until file '{path}' has owner '{expectedOwner}' and group '{expectedGroup}' on {component}")
  public void waitUntilFileHasOwnerAndGroup(SsmComponent component, String path,
      String expectedOwner, String expectedGroup) {
    waitUntil(() -> checkOwner(component, path, expectedOwner, expectedGroup), SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until file '{path}' has replication factor '{expectedReplication}' on {component}")
  public void waitUntilFileHasReplication(SsmComponent component, String path, int expectedReplication) {
    waitUntil(() -> checkReplication(component, path, String.valueOf(expectedReplication)),
        SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until file '{path}' has modification time {expectedModificationTime} on {component}")
  public void waitUntilFileHasModificationTime(SsmComponent component, String path,
      long expectedModificationTime) {
    waitUntil(() -> checkModificationTime(component, path, expectedModificationTime),
        SYNC_ACTION_TIMEOUT);
  }

  @Step("Wait until modification time of file '{path}' on {component} is greater than {time}")
  public void waitUntilFileModificationTimeAfter(SsmComponent component, String path, long time) {
    waitUntil(() -> {
      try {
        assertThat(getModificationTime(component, path))
            .as("Modification time of file '%s' on %s", path, component)
            .isGreaterThan(time);
      } catch (UncheckedIOException e) {
        throw new AssertionError(
            format("File '%s' is not available on %s: %s", path, component, e.getMessage()), e);
      }
    }, SYNC_ACTION_TIMEOUT);
  }

  private <T> T withFileSystem(SsmComponent component, FileSystemOperation<T> operation) {
    try {
      return operation.apply(getFileSystem(component));
    } catch (IOException e) {
      throw new UncheckedIOException(
          format("HDFS operation on %s (%s) failed", component, getFileSystemUri(component)), e);
    }
  }

  private FileSystem getFileSystem(SsmComponent component) throws IOException {
    String uri = getFileSystemUri(component);
    try {
      Configuration conf = new Configuration();
      conf.setBoolean(REPLACE_DATANODE_ON_FAILURE_KEY, false);
      return FileSystem.get(URI.create(uri), conf, HDFS_USER);
    } catch (InterruptedException e) {
      throw new IOException(format("Interrupted while connecting to %s (%s)", component, uri), e);
    }
  }

  private String getFileSystemUri(SsmComponent component) {
    switch (component) {
      case HADOOP_NAMENODE:
        return sourceFsUri;
      case TARGET_NAMENODE:
        return targetFsUri;
      default:
        throw new IllegalArgumentException("Unsupported HDFS cluster component: " + component);
    }
  }

  @FunctionalInterface
  private interface FileSystemOperation<T> {
    T apply(FileSystem fileSystem) throws IOException;
  }
}
