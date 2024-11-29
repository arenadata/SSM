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

import org.apache.hadoop.fs.Options;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicy;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.util.Map;

/**
 * An action to set replication policy for a dir or convert a file to another one in replication policy.
 * Default value is used for argument of bufSize if its value is not given in this action.
 */
@ActionSignature(
    actionId = "unec",
    displayName = "unec",
    usage = HdfsAction.FILE_PATH + " $src " + ErasureCodingBase.BUF_SIZE + " $bufSize"
)
public class UnErasureCodingAction extends ErasureCodingBase {
  private static final Logger LOG =
      LoggerFactory.getLogger(UnErasureCodingAction.class);

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.ecPolicyName = REPLICATION_POLICY_NAME;
    this.ecTmpPath = getPathArg(EC_TMP);
    this.bufferSize = isArgPresent(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUF_SIZE;
    this.progress = 0.0F;
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH);

    HdfsFileStatus fileStatus = (HdfsFileStatus) localFileSystem.getFileStatus(srcPath);
    ErasureCodingPolicy srcEcPolicy = fileStatus.getErasureCodingPolicy();

    // if ecPolicy is null, it means replication.
    if (srcEcPolicy == null) {
      this.progress = 1.0F;
      appendLog(MATCH_RESULT);
      return;
    }
    if (fileStatus.isDir()) {
      localFileSystem.setErasureCodingPolicy(srcPath, ecPolicyName);
      progress = 1.0F;
      appendLog(DIR_RESULT);
      return;
    }

    try {
      convert(fileStatus);
      setAttributes(fileStatus);
      localFileSystem.rename(ecTmpPath, srcPath, Options.Rename.OVERWRITE);
      appendLog(CONVERT_RESULT);
      appendLog(String.format("The previous EC policy is %s.", srcEcPolicy.getName()));
      appendLog(String.format("The current EC policy is %s.", REPLICATION_POLICY_NAME));
    } catch (ActionException ex) {
      try {
        if (localFileSystem.exists(ecTmpPath)) {
          localFileSystem.delete(ecTmpPath, false);
        }
      } catch (IOException e) {
        LOG.error("Failed to delete tmp file created during the conversion!");
      }
      throw new ActionException(ex);
    }
  }

  @Override
  public FsType localFsType() {
    return FsType.DEFAULT_HDFS;
  }
}