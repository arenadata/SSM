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
import org.apache.hadoop.fs.Options;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.hdfs.StreamCopyHandler;
import org.smartdata.model.CompressionFileState;
import org.smartdata.model.FileState;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import static org.smartdata.hdfs.action.CompressionAction.BUF_SIZE;

/**
 * This class is used to decompress file.
 */
@ActionSignature(
    actionId = "decompress",
    displayName = "decompress",
    usage = HdfsAction.FILE_PATH
        + " $file "
        + BUF_SIZE
        + " $bufSize "
)
public class DecompressionAction extends HdfsAction {
  public static final String COMPRESS_TMP = "-compressTmp";
  public static final int DEFAULT_BUFFER_SIZE = 64 * 1024;

  private float progress;
  private int buffSize;
  private Path compressTmpPath;
  private Path filePath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.filePath = getPathArg(FILE_PATH);
    this.compressTmpPath = getPathArg(COMPRESS_TMP);
    this.progress = 0.0F;
    this.buffSize = args.containsKey(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUFFER_SIZE;
  }

  private void validate() throws Exception {
    validateNonEmptyArgs(FILE_PATH, COMPRESS_TMP);

    if (!localFileSystem.exists(filePath)) {
      throw new ActionException(
          "Failed to execute Compression Action: the given file doesn't exist!");
    }

    // Consider directory case.
    if (localFileSystem.getFileStatus(filePath).isDirectory()) {
      throw new ActionException("Decompression is not applicable to a directory.");
    }
  }

  protected void execute() throws Exception {
    validate();

    FileState fileState = HadoopUtil.getFileState(localFileSystem, filePath);
    if (!(fileState instanceof CompressionFileState)) {
      throw new ActionException("File is not compressed: " + filePath);
    }

    FileStatus compressedFileStatus = localFileSystem.getFileStatus(filePath);

    try (InputStream in = localFileSystem.open(filePath);
         // No need to lock the file by append operation,
         // since compressed file cannot be modified.
         OutputStream out = localFileSystem.create(compressTmpPath, true)) {

      // Keep storage policy consistent.
      String storagePolicyName = localFileSystem.getStoragePolicy(filePath).getName();
      if (!storagePolicyName.equals("UNDEF")) {
        localFileSystem.setStoragePolicy(compressTmpPath, storagePolicyName);
      }

      StreamCopyHandler.of(in, out)
          .count(compressedFileStatus.getLen())
          .bufferSize(buffSize)
          .closeStreams(false)
          .progressConsumer(this::updateProgress)
          .build()
          .runCopy();

      // Overwrite the original file with decompressed data
      localFileSystem.setOwner(compressTmpPath,
          compressedFileStatus.getOwner(),
          compressedFileStatus.getGroup());
      localFileSystem.setPermission(compressTmpPath, compressedFileStatus.getPermission());
      localFileSystem.rename(compressTmpPath, filePath, Options.Rename.OVERWRITE);
      appendLog("The given file is successfully decompressed by codec: " +
          ((CompressionFileState) fileState).getCompressionImpl());
    }
  }

  private void updateProgress(float progress) {
    this.progress = progress;
  }

  @Override
  public float getProgress() {
    return this.progress;
  }
}
