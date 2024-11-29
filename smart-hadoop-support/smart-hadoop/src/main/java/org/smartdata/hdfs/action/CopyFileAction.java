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

import com.google.common.collect.Sets;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.StreamCopyHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.GROUP;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.OWNER;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.PERMISSIONS;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.REPLICATION_NUMBER;

/**
 * An action to copy a single file from src to destination.
 * If dest doesn't contains "hdfs" prefix, then destination will be set to
 * current cluster, i.e., copy between dirs in current cluster.
 * Note that destination should contains filename.
 */
@ActionSignature(
    actionId = "copy",
    displayName = "copy",
    usage = HdfsAction.FILE_PATH + " $src "
        + CopyFileAction.DEST_PATH + " $dest "
        + CopyFileAction.OFFSET_INDEX + " $offset "
        + CopyFileAction.LENGTH + " $length "
        + CopyFileAction.BUF_SIZE + " $size "
        + CopyFileAction.PRESERVE + " $attributes"
        + CopyFileAction.FORCE
)
public class CopyFileAction extends CopyPreservedAttributesAction {
  public static final String BUF_SIZE = "-bufSize";
  public static final String DEST_PATH = "-dest";
  public static final String OFFSET_INDEX = "-offset";
  public static final String LENGTH = "-length";
  public static final String COPY_CONTENT = "-copyContent";
  public static final String FORCE = "-force";
  public static final Set<PreserveAttribute> DEFAULT_PRESERVE_ATTRIBUTES
      = Sets.newHashSet(OWNER, GROUP, PERMISSIONS);

  private Path srcPath;
  private Path destPath;
  private long offset;
  private long length;
  private int bufferSize;
  private boolean copyContent;
  private boolean fullCopyAppend;

  private Set<PreserveAttribute> preserveAttributes;

  private FileStatus srcFileStatus;

  public CopyFileAction() {
    super(DEFAULT_PRESERVE_ATTRIBUTES);
    this.offset = 0;
    this.length = 0;
    this.bufferSize = 64 * 1024;
    this.copyContent = true;
    this.fullCopyAppend = false;
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.destPath = getPathArg(DEST_PATH);
    if (args.containsKey(BUF_SIZE)) {
      bufferSize = Integer.parseInt(args.get(BUF_SIZE));
    }
    if (args.containsKey(OFFSET_INDEX)) {
      offset = Long.parseLong(args.get(OFFSET_INDEX));
    }
    if (args.containsKey(LENGTH)) {
      length = Long.parseLong(args.get(LENGTH));
    }
    if (args.containsKey(COPY_CONTENT)) {
      copyContent = Boolean.parseBoolean(args.get(COPY_CONTENT));
    }
    fullCopyAppend = args.containsKey(FORCE);
  }

  @Override
  protected void execute() throws Exception {
    FileSystem srcFileSystem = getFileSystemFor(srcPath);
    FileSystem destFileSystem = getFileSystemFor(destPath);

    validateArgs(srcFileSystem);

    preserveAttributes = parsePreserveAttributes();
    srcFileStatus = srcFileSystem.getFileStatus(srcPath);

    if (!copyContent) {
      appendLog("Src and dest files are equal, no need to copy content");
    } else if (length != 0) {
      copyWithOffset(srcFileSystem, destFileSystem, bufferSize, offset, length);
    } else if (offset == 0) {
      copySingleFile(srcFileSystem, destFileSystem);
    }

    copyFileAttributes(srcFileStatus, destPath, destFileSystem, preserveAttributes);

    appendLog("Copy Successfully!!");
  }

  private void validateArgs(FileSystem srcFileSystem) throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST_PATH);
    if (!srcFileSystem.exists(srcPath)) {
      throw new ActionException("Src file doesn't exist!");
    }
  }

  private void copySingleFile(
      FileSystem srcFileSystem, FileSystem destFileSystem) throws IOException {
    appendLog(
        String.format("Copy the whole file with length %s", srcFileStatus.getLen()));
    copyWithOffset(srcFileSystem, destFileSystem, bufferSize, 0, srcFileStatus.getLen());
  }

  private void copyWithOffset(
      FileSystem srcFileSystem,
      FileSystem destFileSystem,
      int bufferSize, long offset, long length) throws IOException {
    try {
      copyWithOffsetInternal(srcFileSystem, destFileSystem, bufferSize, offset, length);
    } catch (UnsupportedOperationException unsupportedOperationException) {
      if (fullCopyAppend && offset != 0) {
        appendLog(
            String.format("Seems like target FS doesn't support appends. "
                + "Trying to copy the entire source file of size %s", srcFileStatus.getLen()));

        copySingleFile(srcFileSystem, destFileSystem);
        return;
      }
      throw unsupportedOperationException;
    }
  }

  private void copyWithOffsetInternal(
      FileSystem srcFileSystem,
      FileSystem destFileSystem,
      int bufferSize, long offset, long length) throws IOException {
    appendLog(
        String.format("Copy with offset %s and length %s", offset, length));

    try (InputStream in = srcFileSystem.open(srcPath);
         OutputStream out = getOutputStream(destFileSystem, offset)) {
      StreamCopyHandler.of(in, out)
          .offset(offset)
          .count(length)
          .bufferSize(bufferSize)
          .closeStreams(false)
          .build()
          .runCopy();
    }
  }

  private OutputStream getOutputStream(
      FileSystem fileSystem, long offset) throws IOException {
    Optional<FileStatus> destFileStatus = getFileStatus(fileSystem, destPath)
        .map(this::validateDestFile);

    if (!destFileStatus.isPresent() || offset == 0) {
      short replication = getReplication(fileSystem.getDefaultReplication(destPath));
      return fileSystem.create(destPath, replication);
    }

    if (destFileStatus.get().getLen() != offset) {
      appendLog("Truncating existing file " + destPath + " to the new length " + offset);
      fileSystem.truncate(destPath, offset);
    }

    appendLog("Appending to existing file " + destPath);
    return fileSystem.append(destPath);
  }

  private FileStatus validateDestFile(FileStatus destFileStatus) {
    if (destFileStatus.getLen() < offset) {
      String errorMessage = String.format(
          "Destination file %s is shorter than it should be "
              + "- expected min length: %d, actual length: %d",
          destFileStatus.getPath(), offset, destFileStatus.getLen());
      throw new IllegalStateException(errorMessage);
    }

    return destFileStatus;
  }

  public static void validatePreserveArg(String option) {
    PreserveAttribute.fromOption(option);
  }

  private short getReplication(Short defaultReplication) {
    return preserveAttributes.contains(REPLICATION_NUMBER)
        ? srcFileStatus.getReplication()
        : defaultReplication;
  }
}
