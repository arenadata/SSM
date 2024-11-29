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

import org.apache.hadoop.fs.FileChecksum;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RemoteIterator;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;

import static org.smartdata.utils.PathUtil.getRawPath;

@ActionSignature(
    actionId = "checksum",
    displayName = "checksum",
    usage = HdfsAction.FILE_PATH + " $src "
)
public class CheckSumAction extends HdfsActionWithRemoteClusterSupport {
  private String fileRawPath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.fileRawPath = args.get(FILE_PATH);
  }

  @Override
  protected void preExecute() throws Exception {
    validateNonEmptyArg(FILE_PATH);
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    if (fileRawPath.charAt(fileRawPath.length() - 1) == '*') {
      String directoryPath = fileRawPath.substring(0, fileRawPath.length() - 1);
      directoryContentChecksum(fileSystem, new Path(directoryPath));
      return;
    }

    Path filePath = new Path(fileRawPath);
    FileStatus fileStatus = fileSystem.getFileStatus(filePath);

    if (fileStatus.isDirectory()) {
      appendResult("This is a directory which has no checksum result!");
      return;
    }

    checksum(fileSystem, filePath, fileStatus.getLen());
  }

  private void directoryContentChecksum(
      FileSystem fileSystem, Path directoryPath) throws Exception {
    RemoteIterator<FileStatus> statusIter;
    try {
      statusIter = fileSystem.listStatusIterator(directoryPath);
    } catch (FileNotFoundException e) {
      throw new ActionException("Provided directory doesn't exist: " + directoryPath);
    }

    while (statusIter.hasNext()) {
      try {
        FileStatus status = statusIter.next();
        checksum(fileSystem, status.getPath(), status.getLen());
      } catch (FileNotFoundException e) {
        // skip file if it was deleted between listing and checksum requests
      }
    }
  }

  private void checksum(FileSystem fileSystem,
      Path path, long fileSize) throws IOException {
    FileChecksum md5 = fileSystem.getFileChecksum(path, fileSize);

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);
    md5.write(dataStream);
    byte[] bytes = byteStream.toByteArray();
    appendResult(
        String.format("%s\t%s\t%s",
            getRawPath(path),
            md5.getAlgorithmName(),
            byteArray2HexString(bytes)
        ));
  }

  private static String byteArray2HexString(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return null;
    }
    char[] chars = new char[bytes.length * 2];
    final char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int i = 0, j = 0; i < bytes.length; i++) {
      chars[j++] = hexDigits[bytes[i] >> 4 & 0x0f];
      chars[j++] = hexDigits[bytes[i] & 0x0f];
    }
    return new String(chars);
  }
}
