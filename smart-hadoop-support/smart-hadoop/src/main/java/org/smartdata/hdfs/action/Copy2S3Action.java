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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.StreamCopyHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.utils.PathUtil.getRawPath;

/**
 * An action to copy a single file from src to destination.
 * If dest doesn't contains "hdfs" prefix, then destination will be set to
 * current cluster, i.e., copy between dirs in current cluster.
 * Note that destination should contains filename.
 */
@ActionSignature(
    actionId = "copy2s3",
    displayName = "copy2s3",
    usage = HdfsAction.FILE_PATH + " $src " + Copy2S3Action.DEST +
        " $dest " + Copy2S3Action.BUF_SIZE + " $size"
)
public class Copy2S3Action extends HdfsActionWithRemoteClusterSupport {
  public static final String BUF_SIZE = "-bufSize";
  public static final String SRC = HdfsAction.FILE_PATH;
  public static final String DEST = "-dest";

  public static final String S3_SCHEME_PREFIX = "s3";
  public static final int DEFAULT_BUFFER_SIZE = 64 * 1024;

  private Path srcPath;
  private Path destPath;
  private int bufferSize;

  @Override
  public void init(Map<String, String> args) {
    withDefaultFs();
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.destPath = getPathArg(DEST);
    this.bufferSize = isArgPresent(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUFFER_SIZE;
  }

  @Override
  protected void preExecute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST);

    boolean isS3Scheme = Optional.ofNullable(destPath.toUri())
        .map(URI::getScheme)
        .filter(scheme -> scheme.startsWith(S3_SCHEME_PREFIX))
        .isPresent();

    if (!isS3Scheme) {
      throw new ActionException("Destination is not a s3:// path: " + destPath);
    }
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST);
    if (!fileSystem.exists(srcPath)) {
      throw new ActionException("CopyFile Action fails, file doesn't exist!");
    }

    appendLog(
        String.format("Copy from %s to %s", srcPath, destPath));
    copySingleFile(fileSystem);
    appendLog("Copy Successfully!!");
    setXAttribute(fileSystem);
  }

  private void setXAttribute(FileSystem fileSystem) throws IOException {
    String name = "user.coldloc";
    fileSystem.setXAttr(srcPath, name, getRawPath(destPath).getBytes());
    appendLog(" SetXattr feature is set - srcPath  " + srcPath + " destination: " + destPath);
  }

  private void copySingleFile(FileSystem fileSystem) throws IOException {
    try (InputStream in = fileSystem.open(srcPath);
         OutputStream out = getDestOutPutStream()) {

      StreamCopyHandler.of(in, out)
          .closeStreams(false)
          .count(fileSystem.getFileStatus(srcPath).getLen())
          .bufferSize(bufferSize)
          .build()
          .runCopy();
    }
  }

  private OutputStream getDestOutPutStream() throws IOException {
    FileSystem destFileSystem = destPath.getFileSystem(getConf());
    return destFileSystem.create(destPath, true);
  }
}
