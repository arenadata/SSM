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
import org.apache.commons.lang3.SerializationUtils;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.client.HdfsDataOutputStream;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.apache.hadoop.io.IOUtils;
import org.smartdata.SmartConstants;
import org.smartdata.SmartFilePermission;
import org.smartdata.action.Utils;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.CompatibilityHelperLoader;
import org.smartdata.model.CompactFileState;
import org.smartdata.model.FileContainerInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

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

  private float status = 0f;
  private String smallFiles = null;
  private String containerFile = null;
  private String containerFilePermission = null;
  private String xAttrNameFileSate = null;
  private String xAttrNameCheckSum = null;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.xAttrNameFileSate = SmartConstants.SMART_FILE_STATE_XATTR_NAME;
    this.xAttrNameCheckSum = SmartConstants.SMART_FILE_CHECKSUM_XATTR_NAME;
    this.smallFiles = args.get(FILE_PATH);
    this.containerFile = args.get(CONTAINER_FILE);
    this.containerFilePermission = args.get(CONTAINER_FILE_PERMISSION);
  }

  @Override
  protected void execute() throws Exception {
    // Get small file list
    if (smallFiles == null || smallFiles.isEmpty()) {
      throw new IllegalArgumentException(
          String.format("Invalid small files: %s.", smallFiles));
    }
    ArrayList<String> smallFileList = new Gson().fromJson(
        smallFiles, new TypeToken<ArrayList<String>>() {
        }.getType());
    if (smallFileList == null || smallFileList.isEmpty()) {
      throw new IllegalArgumentException(
          String.format("Invalid small files: %s.", smallFiles));
    }

    // Get container file path
    if (containerFile == null || containerFile.isEmpty()) {
      throw new IllegalArgumentException(
          String.format("Invalid container file: %s.", containerFile));
    }

    // Get container file permission
    SmartFilePermission filePermission = null;
    if (containerFilePermission != null && !containerFilePermission.isEmpty()) {
      filePermission = new Gson().fromJson(
          containerFilePermission, new TypeToken<SmartFilePermission>() {
          }.getType());
    }
    appendLog(String.format("Action starts at %s : compact small files to %s.",
        Utils.getFormatedCurrentTime(), containerFile));

    // Get initial offset and output stream
    // Create container file and set permission if not exists
    long offset;
    OutputStream out;
    boolean isContainerFileExist = dfsClient.exists(containerFile);
    if (isContainerFileExist) {
      offset = dfsClient.getFileInfo(containerFile).getLen();
      out = CompatibilityHelperLoader.getHelper()
          .getDFSClientAppend(dfsClient, containerFile, 64 * 1024, offset);
    } else {
      out = dfsClient.create(containerFile, true);
      if (filePermission != null) {
        dfsClient.setOwner(
            containerFile, filePermission.getOwner(), filePermission.getGroup());
        dfsClient.setPermission(
            containerFile, new FsPermission(filePermission.getPermission()));
      }
      offset = 0L;
    }
    List<CompactFileState> compactFileStates = new ArrayList<>();

    for (String smallFile : smallFileList) {
      if ((smallFile != null) && !smallFile.isEmpty() && dfsClient.exists(smallFile)) {
        HdfsDataOutputStream append =
            (HdfsDataOutputStream) CompatibilityHelperLoader.getHelper().getDFSClientAppend(dfsClient, smallFile, 1024);
        long fileLen = dfsClient.getFileInfo(smallFile).getLen();
        if (fileLen > 0) {
          try (InputStream in = dfsClient.open(smallFile)) {
            // Copy bytes of small file to container file
            IOUtils.copyBytes(in, out, 4096);

            // Truncate small file, add file container info to XAttr
            CompactFileState compactFileState = new CompactFileState(
                smallFile, new FileContainerInfo(containerFile, offset, fileLen));
            append.close();
            truncateAndSetXAttr(smallFile, compactFileState);

            // Update compact file state map, offset, status, and log
            compactFileStates.add(compactFileState);
            offset += fileLen;
            this.status = (smallFileList.indexOf(smallFile) + 1.0f)
                / smallFileList.size();
            appendLog(String.format(
                "Compact %s to %s successfully.", smallFile, containerFile));
          } catch (IOException e) {
            // Close append, output streams and put compact file state map into action result
            if (append != null) {
              append.close();
            }
            if (out != null) {
              out.close();
              appendResult(new Gson().toJson(compactFileStates));
            }
            if (!isContainerFileExist && compactFileStates.isEmpty()) {
              dfsClient.delete(containerFile, false);
            }
            throw e;
          }
        }
      }
    }

    appendResult(new Gson().toJson(compactFileStates));
    if (out != null) {
      out.close();
    }
    if (!isContainerFileExist && compactFileStates.isEmpty()) {
      dfsClient.delete(containerFile, false);
    }
    appendLog(String.format(
        "Compact all the small files to %s successfully.", containerFile));
  }

  /**
   * Truncate small file and set XAttr contains file container info.
   * To truncate the file length to zero, we delete the original file, then
   * create a new empty file with a different fid.
   */
  private void truncateAndSetXAttr(String path, CompactFileState compactFileState)
      throws IOException {
    // Save original metadata of small file
    HdfsFileStatus fileStatus = dfsClient.getFileInfo(path);
    Map<String, byte[]> xAttr = dfsClient.getXAttrs(path);
    byte[] checksumBytes = getCheckSumByteArray(path, fileStatus.getLen());

    // Delete file
    dfsClient.delete(path, false);

    // Create file with empty content.
    OutputStream out = dfsClient.create(path, true);
    if (out != null) {
      out.close();
    }

    // Set metadata
    dfsClient.setOwner(path, fileStatus.getOwner(), fileStatus.getGroup());
    dfsClient.setPermission(path, fileStatus.getPermission());
    dfsClient.setReplication(path, fileStatus.getReplication());
    dfsClient.setStoragePolicy(path, "Cold");
    dfsClient.setTimes(path, fileStatus.getModificationTime(),
        fileStatus.getAccessTime());

    for(Map.Entry<String, byte[]> entry : xAttr.entrySet()) {
      dfsClient.setXAttr(path, entry.getKey(), entry.getValue(),
          EnumSet.of(XAttrSetFlag.CREATE, XAttrSetFlag.REPLACE));
    }

    // Set file container info into XAttr
    dfsClient.setXAttr(path,
        xAttrNameFileSate, SerializationUtils.serialize(compactFileState),
        EnumSet.of(XAttrSetFlag.CREATE));
    dfsClient.setXAttr(path, xAttrNameCheckSum,
        checksumBytes, EnumSet.of(XAttrSetFlag.CREATE));
  }

  private byte[] getCheckSumByteArray(String path, long length)
      throws IOException {
    return dfsClient.getFileChecksum(path, length).getBytes();
  }

  @Override
  public float getProgress() {
    return this.status;
  }

  @Override
  public DfsClientType dfsClientType() {
    return DfsClientType.DEFAULT_HDFS;
  }
}
