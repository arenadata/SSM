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

import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
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

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@Service
public class HdfsStep {
  private static final String HDFS_USER = "root";
  private static final String REPLICATION_KEY = "dfs.replication";
  private static final String REPLACE_DATANODE_ON_FAILURE_KEY =
      "dfs.client.block.write.replace-datanode-on-failure.enable";

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
      try (OutputStream out = fileSystem.create(new Path(path), true)) {
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
        return new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
      }
    });
  }

  @Step("Get permissions of '{path}' on {component}")
  public String getPermissions(SsmComponent component, String path) {
    short permissions = withFileSystem(component, fileSystem ->
        fileSystem.getFileStatus(new Path(path)).getPermission().toOctal());
    return String.valueOf(permissions);
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
      log.debug("Connecting to HDFS cluster {} ({})", component, uri);
      Configuration conf = new Configuration();
      conf.setInt(REPLICATION_KEY, 1);
      conf.setBoolean(REPLACE_DATANODE_ON_FAILURE_KEY, false);
      return FileSystem.get(URI.create(uri), conf, HDFS_USER);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
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
