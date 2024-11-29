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

import lombok.Getter;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.io.IOUtils;
import org.smartdata.SmartConstants;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.smartdata.hdfs.action.SmallFileCompactAction.parseSmallFileList;

/**
 * An action to recovery contents of compacted ssm small files.
 */
@ActionSignature(
    actionId = "uncompact",
    displayName = "uncompact",
    usage = SmallFileUncompactAction.CONTAINER_FILE + " $container_file "
)
public class SmallFileUncompactAction extends HdfsAction {
  public static final String CONTAINER_FILE =
      SmallFileCompactAction.CONTAINER_FILE;

  @Getter
  private float progress;
  private String smallFiles;
  private String xAttrNameFileState;
  private String xAttrNameCheckSum;
  private Path containerFile;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.xAttrNameFileState = SmartConstants.SMART_FILE_STATE_XATTR_NAME;
    this.xAttrNameCheckSum = SmartConstants.SMART_FILE_CHECKSUM_XATTR_NAME;
    this.smallFiles = args.get(FILE_PATH);
    this.containerFile = getPathArg(CONTAINER_FILE);
    this.progress = 0.0f;
  }

  @Override
  protected void execute() throws Exception {
    // Get small file list
    validateNonEmptyArgs(FILE_PATH, CONTAINER_FILE);

    List<String> smallFileList = parseSmallFileList(smallFiles);
    for (int i = 0; i < smallFileList.size(); i++) {
      Path smallFile = new Path(smallFileList.get(i));

      if (localFileSystem.exists(smallFile)) {
        // Get compact input stream
        try (FSDataInputStream in = localFileSystem.open(smallFile);
             // Create new small file
             OutputStream out = localFileSystem.create(smallFile, true)) {

          // Save original metadata of small file and delete original small file
          FileStatus fileStatus = localFileSystem.getFileStatus(smallFile);
          Map<String, byte[]> xAttr = localFileSystem.getXAttrs(smallFile);
          localFileSystem.delete(smallFile, false);

          // Copy contents to original small file
          IOUtils.copyBytes(in, out, 4096);

          // Reset file meta data
          resetFileMeta(fileStatus, xAttr);

          // Set status and update log
          this.progress = (i + 1.0f) / smallFileList.size();
          appendLog("Uncompact successfully: " + smallFile);
        }
      }
    }

    localFileSystem.delete(containerFile, false);
    appendLog(String.format("Uncompact all the small files of %s successfully.", containerFile));
  }

  /**
   * Reset meta data of small file. We should exclude the setting for
   * xAttrNameFileState or xAttrNameCheckSum.
   */
  private void resetFileMeta(FileStatus fileStatus,
      Map<String, byte[]> xAttr) throws IOException {
    localFileSystem.setOwner(fileStatus.getPath(), fileStatus.getOwner(), fileStatus.getGroup());
    localFileSystem.setPermission(fileStatus.getPath(), fileStatus.getPermission());

    for (Map.Entry<String, byte[]> entry : xAttr.entrySet()) {
      if (!entry.getKey().equals(xAttrNameFileState) &&
          !entry.getKey().equals(xAttrNameCheckSum)) {
        localFileSystem.setXAttr(fileStatus.getPath(), entry.getKey(), entry.getValue(),
            EnumSet.of(XAttrSetFlag.CREATE, XAttrSetFlag.REPLACE));
      }
    }
  }

  @Override
  public FsType localFsType() {
    return FsType.DEFAULT_HDFS;
  }
}
