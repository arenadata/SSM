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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import lombok.Getter;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.io.IOUtils;
import org.smartdata.SmartConstants;
import org.smartdata.SmartFilePermission;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.model.CompactFileState;
import org.smartdata.model.FileContainerInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.smartdata.utils.PathUtil.getRawPath;

/**
 * An action to compact small files to a big container file.
 */
@ActionSignature(
    actionId = "compact",
    displayName = "compact",
    usage = HdfsAction.FILE_PATH + " $files "
        + SmallFileCompactAction.CONTAINER_FILE + " $container_file "
)
public class SmallFileCompactAction extends HdfsAction {
  public static final String CONTAINER_FILE = "-containerFile";
  public static final String CONTAINER_FILE_PERMISSION = "-containerFilePermission";

  private static final Type SMALL_FILE_LIST_TYPE =
      new TypeToken<ArrayList<String>>() {
      }.getType();

  @Getter
  private float progress;
  private String smallFiles;
  private Path containerFile;
  private String containerFilePermission;
  private String xAttrNameFileSate;
  private String xAttrNameCheckSum;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.xAttrNameFileSate = SmartConstants.SMART_FILE_STATE_XATTR_NAME;
    this.xAttrNameCheckSum = SmartConstants.SMART_FILE_CHECKSUM_XATTR_NAME;
    this.smallFiles = args.get(FILE_PATH);
    this.containerFile = getPathArg(CONTAINER_FILE);
    this.containerFilePermission = args.get(CONTAINER_FILE_PERMISSION);
    this.progress = 0.0f;
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, CONTAINER_FILE);

    List<String> smallFileList = parseSmallFileList(smallFiles);


    // Get initial offset and output stream
    // Create container file and set permission if not exists
    boolean containerFileExists = localFileSystem.exists(containerFile);
    long offset = containerFileExists
        ? localFileSystem.getFileStatus(containerFile).getLen()
        : 0;

    try (OutputStream out = getContainerOutputStream(containerFileExists)) {
      List<CompactFileState> compactFileStates = new ArrayList<>();

      for (int i = 0; i < smallFileList.size(); ++i) {
        Path smallFile = new Path(smallFileList.get(i));

        long fileLen = getFileStatus(localFileSystem, smallFile)
            .map(FileStatus::getLen)
            .orElse(0L);

        if (fileLen == 0) {
          continue;
        }

        try (InputStream in = localFileSystem.open(smallFile);
             FSDataOutputStream append = localFileSystem.append(smallFile, 1024)) {
          // Copy bytes of small file to container file
          IOUtils.copyBytes(in, out, 4096);

          // Truncate small file, add file container info to XAttr
          CompactFileState compactFileState = new CompactFileState(
              smallFileList.get(i), new FileContainerInfo(getRawPath(containerFile), offset, fileLen));
          append.close();
          truncateAndSetXAttr(smallFile, compactFileState);

          // Update compact file state map, offset, status, and log
          compactFileStates.add(compactFileState);
          offset += fileLen;
          this.progress = (i + 1.0f) / smallFileList.size();
          appendLog(String.format(
              "Compact %s to %s successfully.", smallFile, containerFile));
        } catch (IOException e) {
          if (out != null) {
            out.close();
            appendResult(new Gson().toJson(compactFileStates));
          }
          if (!containerFileExists && compactFileStates.isEmpty()) {
            localFileSystem.delete(containerFile, false);
          }
          throw e;
        }
      }

      appendResult(new Gson().toJson(compactFileStates));
      if (!containerFileExists && compactFileStates.isEmpty()) {
        localFileSystem.delete(containerFile, false);
      }

      appendLog(String.format(
          "Compact all the small files to %s successfully.", containerFile));
    }
  }

  private OutputStream getContainerOutputStream(boolean containerFileExists) throws IOException {
    if (containerFileExists) {
      return localFileSystem.append(containerFile, 64 * 1024);
    }

    OutputStream out = localFileSystem.create(containerFile, true);

    if (StringUtils.isNotBlank(containerFilePermission)) {
      SmartFilePermission filePermission = new Gson().fromJson(
          containerFilePermission, SmartFilePermission.class);

      localFileSystem.setOwner(
          containerFile, filePermission.getOwner(), filePermission.getGroup());
      localFileSystem.setPermission(
          containerFile, new FsPermission(filePermission.getPermission()));
    }

    return out;
  }

  /**
   * Truncate small file and set XAttr contains file container info.
   * To truncate the file length to zero, we delete the original file, then
   * create a new empty file with a different fid.
   */
  private void truncateAndSetXAttr(Path path, CompactFileState compactFileState)
      throws IOException {
    // Save original metadata of small file
    FileStatus fileStatus = localFileSystem.getFileStatus(path);
    Map<String, byte[]> xAttr = localFileSystem.getXAttrs(path);
    byte[] checksumBytes = getCheckSumByteArray(path, fileStatus.getLen());

    // Delete file
    localFileSystem.delete(path, false);

    // Create file with empty content.
    try (OutputStream ignored = localFileSystem.create(path, true)) {
    }

    // Set metadata
    localFileSystem.setOwner(path, fileStatus.getOwner(), fileStatus.getGroup());
    localFileSystem.setPermission(path, fileStatus.getPermission());
    localFileSystem.setReplication(path, fileStatus.getReplication());
    localFileSystem.setStoragePolicy(path, "Cold");
    localFileSystem.setTimes(path, fileStatus.getModificationTime(),
        fileStatus.getAccessTime());

    for (Map.Entry<String, byte[]> entry : xAttr.entrySet()) {
      localFileSystem.setXAttr(path, entry.getKey(), entry.getValue(),
          EnumSet.of(XAttrSetFlag.CREATE, XAttrSetFlag.REPLACE));
    }

    // Set file container info into XAttr
    localFileSystem.setXAttr(path,
        xAttrNameFileSate, SerializationUtils.serialize(compactFileState),
        EnumSet.of(XAttrSetFlag.CREATE));
    localFileSystem.setXAttr(path, xAttrNameCheckSum,
        checksumBytes, EnumSet.of(XAttrSetFlag.CREATE));
  }

  private byte[] getCheckSumByteArray(Path path, long length)
      throws IOException {
    return localFileSystem.getFileChecksum(path, length).getBytes();
  }

  @Override
  public FsType localFsType() {
    return FsType.DEFAULT_HDFS;
  }

  static List<String> parseSmallFileList(String rawFiles) {
    List<String> smallFileList = new Gson()
        .fromJson(rawFiles, SMALL_FILE_LIST_TYPE);
    if (CollectionUtils.isEmpty(smallFileList)) {
      throw new IllegalArgumentException(
          String.format("Invalid small files: %s.", rawFiles));
    }

    return smallFileList;
  }

}
