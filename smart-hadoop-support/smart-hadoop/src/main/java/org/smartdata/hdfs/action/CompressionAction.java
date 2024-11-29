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
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.mutable.MutableFloat;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Options;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.hdfs.CompressionCodecFactory;
import org.apache.hadoop.hdfs.SmartCompressorStream;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.CompressionFileInfo;
import org.smartdata.model.CompressionFileState;
import org.smartdata.utils.StringUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import static org.smartdata.SmartConstants.SMART_FILE_STATE_XATTR_NAME;
import static org.smartdata.utils.PathUtil.getRawPath;

/**
 * This action is used to compress a file.
 */
@ActionSignature(
    actionId = "compress",
    displayName = "compress",
    usage =
        HdfsAction.FILE_PATH
            + " $file "
            + CompressionAction.BUF_SIZE
            + " $bufSize "
            + CompressionAction.CODEC
            + " $codec"
)
public class CompressionAction extends HdfsAction {
  public static final String COMPRESS_TMP = "-compressTmp";
  public static final String BUF_SIZE = "-bufSize";
  public static final String CODEC = "-codec";

  private static final Set<String> SUPPORTED_CODECS =
      CompressionCodecFactory.getInstance().getSupportedCodecs();

  private final Gson compressionInfoSerializer;

  private Path filePath;
  private MutableFloat progress;

  // bufferSize is also chunk size.
  // This default value limits the minimum buffer size.
  private int bufferSize = 1024 * 1024;
  private int maxSplit;
  // Can be set in config or action arg.
  private String compressCodec;
  // Specified by user in action arg.
  private int userDefinedBufferSize;

  private CompressionFileState compressionFileState;

  private Path compressTmpPath;

  public CompressionAction() {
    this.compressionInfoSerializer = new Gson();
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.compressCodec = getContext().getConf().get(
        SmartConfKeys.SMART_COMPRESSION_CODEC,
        SmartConfKeys.SMART_COMPRESSION_CODEC_DEFAULT);
    this.maxSplit = getContext().getConf().getInt(
        SmartConfKeys.SMART_COMPRESSION_MAX_SPLIT,
        SmartConfKeys.SMART_COMPRESSION_MAX_SPLIT_DEFAULT);
    this.filePath = getPathArg(FILE_PATH);
    if (args.containsKey(BUF_SIZE) && !args.get(BUF_SIZE).isEmpty()) {
      this.userDefinedBufferSize = (int) StringUtil.parseToByte(args.get(BUF_SIZE));
    }
    this.compressCodec = args.get(CODEC) != null ? args.get(CODEC) : compressCodec;
    // This is a temp path for compressing a file.
    this.compressTmpPath = getPathArg(COMPRESS_TMP);
    this.progress = new MutableFloat(0.0F);
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, COMPRESS_TMP);

    if (!SUPPORTED_CODECS.contains(compressCodec)) {
      throw new ActionException(
          "Compression Action failed due to unsupported codec: " + compressCodec);
    }

    if (!localFileSystem.exists(filePath)) {
      throw new ActionException(
          "Failed to execute Compression Action: the given file doesn't exist!");
    }

    FileStatus srcFileStatus = localFileSystem.getFileStatus(filePath);
    // Consider directory case.
    if (srcFileStatus.isDirectory()) {
      appendLog("Compression is not applicable to a directory.");
      return;
    }
    // Generate compressed file
    compressionFileState = new CompressionFileState(getRawPath(filePath), bufferSize, compressCodec);
    compressionFileState.setOriginalLength(srcFileStatus.getLen());

    CompressionFileInfo compressionFileInfo;
    if (srcFileStatus.getLen() == 0) {
      compressionFileInfo = new CompressionFileInfo(false, compressionFileState);
    } else {
      try (
          // SmartDFSClient will fail to open compressing file with PROCESSING FileStage
          // set by Compression scheduler. But considering DfsClient may be used, we use
          // append operation to lock the file to avoid any modification.
          OutputStream lockStream = localFileSystem.append(filePath, bufferSize);

          FSDataInputStream in = localFileSystem.open(filePath);
          OutputStream out = localFileSystem.create(compressTmpPath,
              true,
              getLocalDfsClient().getConf().getIoBufferSize(),
              srcFileStatus.getReplication(),
              srcFileStatus.getBlockSize())
      ) {

        appendLog("File length: " + srcFileStatus.getLen());
        bufferSize = getActualBuffSize(srcFileStatus.getLen());

        String storagePolicyName = localFileSystem.getStoragePolicy(filePath).getName();
        if (!storagePolicyName.equals("UNDEF")) {
          localFileSystem.setStoragePolicy(compressTmpPath, storagePolicyName);
        }

        compress(in, out);
        FileStatus destFileStatus = localFileSystem.getFileStatus(compressTmpPath);
        localFileSystem.setOwner(compressTmpPath, srcFileStatus.getOwner(), srcFileStatus.getGroup());
        localFileSystem.setPermission(compressTmpPath, srcFileStatus.getPermission());
        compressionFileState.setCompressedLength(destFileStatus.getLen());
        appendLog("Compressed file length: " + destFileStatus.getLen());
        compressionFileInfo =
            new CompressionFileInfo(true, getRawPath(compressTmpPath), compressionFileState);
      }
    }

    compressionFileState.setBufferSize(bufferSize);
    appendLog("Compression buffer size: " + bufferSize);
    appendLog("Compression codec: " + compressCodec);
    String compressionInfoJson = compressionInfoSerializer.toJson(compressionFileInfo);
    appendResult(compressionInfoJson);
    if (compressionFileInfo.needReplace()) {
      // Add to temp path
      // Please make sure content write to Xattr is less than 64K
      setXAttr(compressTmpPath, compressionFileState);
      // Rename operation is moved from CompressionScheduler.
      // Thus, modification for original file will be avoided.
      localFileSystem.rename(compressTmpPath, filePath, Options.Rename.OVERWRITE);
    } else {
      // Add to raw path
      setXAttr(filePath, compressionFileState);
    }
  }

  private void compress(InputStream inputStream, OutputStream outputStream) throws IOException {
    // We use 'progress' (a percentage) to track compression progress.
    SmartCompressorStream smartCompressorStream = new SmartCompressorStream(
        inputStream, outputStream, bufferSize, compressionFileState, progress);
    smartCompressorStream.convert();
  }

  private int getActualBuffSize(long fileSize) {
    // The capacity of originalPos and compressedPos is maxSplit (1000, by default) in database
    // Calculated by max number of splits.
    int calculatedBufferSize = (int) (fileSize / maxSplit);
    appendLog("Calculated buffer size: " + calculatedBufferSize);
    appendLog("MaxSplit: " + maxSplit);
    // Determine the actual buffer size
    if (userDefinedBufferSize < bufferSize || userDefinedBufferSize < calculatedBufferSize) {
      if (bufferSize <= calculatedBufferSize) {
        appendLog("User defined buffer size is too small, use the calculated buffer size: "
            + calculatedBufferSize);
      } else {
        appendLog("User defined buffer size is too small, use the default buffer size: "
            + bufferSize);
      }
    }
    return Math.max(Math.max(userDefinedBufferSize, calculatedBufferSize), bufferSize);
  }

  private void setXAttr(Path path, CompressionFileState compressionFileState) throws IOException {
    localFileSystem.setXAttr(path, SMART_FILE_STATE_XATTR_NAME,
        SerializationUtils.serialize(compressionFileState),
        EnumSet.of(XAttrSetFlag.CREATE));
  }

  @Override
  public float getProgress() {
    return progress.getValue();
  }
}
