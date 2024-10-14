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

import org.apache.commons.lang3.StringUtils;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.model.CompressionFileState;
import org.smartdata.model.FileState;

import java.io.IOException;
import java.util.Map;

/**
 * This class is used to check compression status for a given file.
 */
@ActionSignature(
    actionId = "checkcompress",
    displayName = "checkcompress",
    usage = HdfsAction.FILE_PATH
        + " $file "
)
public class CheckCompressAction extends HdfsAction {
  private String srcPath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = args.get(HdfsAction.FILE_PATH);
  }

  @Override
  protected void execute() throws Exception {
    if (StringUtils.isBlank(srcPath)) {
      throw new IOException("File path is not given!");
    }
    // Consider directory case.
    if (dfsClient.getFileInfo(srcPath).isDir()) {
      appendResult("The given path is a directory, " +
          "not applicable to checking compression status.");
      return;
    }
    FileState fileState = HadoopUtil.getFileState(dfsClient, srcPath);
    if (fileState instanceof CompressionFileState) {
      appendLog("The given file has already been compressed by SSM.");

      CompressionFileState compressionFileState = (CompressionFileState) fileState;
      appendResult("The compression codec is " +
          compressionFileState.getCompressionImpl());
      appendResult("The original file length is " +
          compressionFileState.getOriginalLength());
      appendResult("The current file length is " +
          compressionFileState.getCompressedLength());
      return;
    }
    appendResult("The given file is not compressed.");
  }
}
