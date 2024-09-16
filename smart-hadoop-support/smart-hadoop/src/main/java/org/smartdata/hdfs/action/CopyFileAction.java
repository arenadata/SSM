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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.Utils;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.CompatibilityHelper;
import org.smartdata.hdfs.CompatibilityHelperLoader;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.IO_FILE_BUFFER_SIZE_DEFAULT;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.IO_FILE_BUFFER_SIZE_KEY;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.GROUP;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.OWNER;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.PERMISSIONS;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.REPLICATION_NUMBER;
import static org.smartdata.utils.ConfigUtil.toRemoteClusterConfig;

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
)
public class CopyFileAction extends CopyPreservedAttributesAction {

  public static final String BUF_SIZE = "-bufSize";
  public static final String DEST_PATH = "-dest";
  public static final String OFFSET_INDEX = "-offset";
  public static final String LENGTH = "-length";
  public static final String COPY_CONTENT = "-copyContent";
  public static final Set<PreserveAttribute> DEFAULT_PRESERVE_ATTRIBUTES
      = Sets.newHashSet(OWNER, GROUP, PERMISSIONS);

  private String srcPath;
  private String destPath;
  private long offset = 0;
  private long length = 0;
  private int bufferSize = 64 * 1024;
  private boolean copyContent = true;

  private Set<PreserveAttribute> preserveAttributes;

  private FileStatus srcFileStatus;

  public CopyFileAction() {
    super(DEFAULT_PRESERVE_ATTRIBUTES);
  }

  @Override
  public void init(Map<String, String> args) {
    withDefaultFs();
    super.init(args);
    this.srcPath = args.get(FILE_PATH);
    if (args.containsKey(DEST_PATH)) {
      this.destPath = args.get(DEST_PATH);
    }
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
  }

  @Override
  protected void execute() throws Exception {
    validateArgs();
    preserveAttributes = parsePreserveAttributes();

    appendLog(
        String.format("Action starts at %s : Copy from %s to %s",
            Utils.getFormatedCurrentTime(), srcPath, destPath));

    srcFileStatus = getFileStatus(srcPath);

    if (!copyContent) {
      appendLog("Src and dest files are equal, no need to copy content");
    } else if (length != 0) {
      copyWithOffset(srcPath, destPath, bufferSize, offset, length);
    } else if (offset == 0) {
      copySingleFile(srcPath, destPath);
    }

    copyFileAttributes(srcPath, destPath, preserveAttributes);

    appendLog("Copy Successfully!!");
  }

  private void validateArgs() throws Exception {
    if (StringUtils.isBlank(srcPath)) {
      throw new IllegalArgumentException("File parameter is missing.");
    }
    if (StringUtils.isBlank(destPath)) {
      throw new IllegalArgumentException("Dest File parameter is missing.");
    }
    if (!dfsClient.exists(srcPath)) {
      throw new ActionException("Src file doesn't exist!");
    }
  }

  private void copySingleFile(String src, String dest) throws IOException {
    appendLog(
        String.format("Copy the whole file with length %s", srcFileStatus.getLen()));
    copyWithOffset(src, dest, bufferSize, 0, srcFileStatus.getLen());
  }

  private void copyWithOffset(String src, String dest, int bufferSize,
      long offset, long length) throws IOException {
    appendLog(
        String.format("Copy with offset %s and length %s", offset, length));

    try (InputStream in = getSrcInputStream(src);
         OutputStream out = getDestOutPutStream(dest, offset)) {
      //skip offset
      in.skip(offset);
      byte[] buf = new byte[bufferSize];
      long bytesRemaining = length;

      while (bytesRemaining > 0L) {
        int bytesToRead = (int) (Math.min(bytesRemaining, buf.length));
        int bytesRead = in.read(buf, 0, bytesToRead);
        if (bytesRead == -1) {
          break;
        }
        out.write(buf, 0, bytesRead);
        bytesRemaining -= bytesRead;
      }
    }
  }

  private InputStream getSrcInputStream(String src) throws IOException {
    if (src.startsWith("hdfs")) {
      // Copy between different remote clusters
      // Get InputStream from URL
      FileSystem fs = FileSystem.get(URI.create(src), getContext().getConf());
      return fs.open(new Path(src));
    }
    return dfsClient.open(src);
  }

  private OutputStream getDestOutPutStream(String dest, long offset) throws IOException {
    if (dest.startsWith("s3")) {
      // Copy to s3
      FileSystem fs = FileSystem.get(URI.create(dest), getContext().getConf());
      return fs.create(new Path(dest), true);
    }

    if (dest.startsWith("hdfs")) {
      // Copy between different clusters
      // Copy to remote HDFS
      // Get OutPutStream from URL
      Configuration remoteClusterConfig = toRemoteClusterConfig(getContext().getConf());
      FileSystem fs = FileSystem.get(URI.create(dest),  remoteClusterConfig);
      Path destHdfsPath = new Path(dest);

      if (fs.exists(destHdfsPath) && offset != 0) {
        appendLog("Append to existing file " + dest);
        return fs.append(destHdfsPath);
      }

      short replication = getReplication(fs.getDefaultReplication(destHdfsPath));
      return fs.create(
          destHdfsPath,
          true,
          remoteClusterConfig.getInt(
              IO_FILE_BUFFER_SIZE_KEY, IO_FILE_BUFFER_SIZE_DEFAULT),
          replication,
          fs.getDefaultBlockSize(destHdfsPath));
    }

    CompatibilityHelper compatibilityHelper = CompatibilityHelperLoader.getHelper();
    if (preserveAttributes.contains(REPLICATION_NUMBER)) {
      return compatibilityHelper
          .getDFSClientAppend(dfsClient, dest, bufferSize, offset, srcFileStatus.getReplication());
    }

    return compatibilityHelper.getDFSClientAppend(dfsClient, dest, bufferSize, offset);
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
