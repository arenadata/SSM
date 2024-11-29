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

import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Options;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicy;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicyInfo;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicyState;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.util.Map;

/**
 * An action to set an EC policy for a dir or convert a file to another one in an EC policy.
 * Default values are used for arguments of policy & bufSize if their values are not given in this action.
 */
@ActionSignature(
    actionId = "ec",
    displayName = "ec",
    usage = HdfsAction.FILE_PATH + " $src "
        + ErasureCodingAction.EC_POLICY_NAME + " $policy"
        + ErasureCodingBase.BUF_SIZE + " $bufSize"
)
public class ErasureCodingAction extends ErasureCodingBase {
  public static final String EC_POLICY_NAME = "-policy";

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.ecTmpPath = getPathArg(EC_TMP);
    this.ecPolicyName = isArgPresent(EC_POLICY_NAME)
        ? args.get(EC_POLICY_NAME)
        : getConf().getTrimmed(
        DFSConfigKeys.DFS_NAMENODE_EC_SYSTEM_DEFAULT_POLICY,
        DFSConfigKeys.DFS_NAMENODE_EC_SYSTEM_DEFAULT_POLICY_DEFAULT);
    this.bufferSize = isArgPresent(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUF_SIZE;
    this.progress = 0.0F;
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH);

    // keep attribute consistent
    HdfsFileStatus fileStatus = (HdfsFileStatus) localFileSystem.getFileStatus(srcPath);

    validateEcPolicy(ecPolicyName);
    ErasureCodingPolicy srcEcPolicy = fileStatus.getErasureCodingPolicy();
    // if the current ecPolicy is already the target one, no need to convert
    if (srcEcPolicy != null && srcEcPolicy.getName().equals(ecPolicyName)
        // if ecPolicy is null, it means replication.
        || srcEcPolicy == null && ecPolicyName.equals(REPLICATION_POLICY_NAME)) {
      appendLog(MATCH_RESULT);
      this.progress = 1.0F;
      return;
    }

    if (fileStatus.isDir()) {
      localFileSystem.setErasureCodingPolicy(srcPath, ecPolicyName);
      this.progress = 1.0F;
      appendLog(DIR_RESULT);
      return;
    }

    FSDataOutputStream outputStream = null;
    try {
      // a file only with replication policy can be appended.
      if (srcEcPolicy == null) {
        // append the file to acquire the lock to avoid modifying, real appending wouldn't occur.
        outputStream = localFileSystem.append(srcPath, bufferSize);
      }
      convert(fileStatus);
      // The append operation will change the modification time accordingly,
      // so we use the FileStatus obtained before append to set ecTmp file's most attributes
      setAttributes(fileStatus);
      localFileSystem.rename(ecTmpPath, srcPath, Options.Rename.OVERWRITE);
      appendLog(CONVERT_RESULT);
      if (srcEcPolicy == null) {
        appendLog("The previous EC policy is replication.");
      } else {
        appendLog("The previous EC policy is " + srcEcPolicy.getName());
      }
      appendLog("The current EC policy is " + ecPolicyName);
    } catch (ActionException ex) {
      try {
        if (localFileSystem.exists(ecTmpPath)) {
          localFileSystem.delete(ecTmpPath, false);
        }
      } catch (IOException e) {
        appendLog("Failed to delete tmp file created during the conversion!" + ex.getMessage());
      }
      throw new ActionException(ex);
    } finally {
      if (outputStream != null) {
        try {
          outputStream.close();
        } catch (IOException ex) {
          // Hide the expected exception that the original file is missing.
        }
      }
    }
  }

  public void validateEcPolicy(String ecPolicyName) throws Exception {
    ErasureCodingPolicyState ecPolicyState = localFileSystem.getAllErasureCodingPolicies()
        .stream()
        .filter(policyInfo -> policyInfo.getPolicy().getName().equals(ecPolicyName))
        .map(ErasureCodingPolicyInfo::getState)
        .findFirst()
        .orElse(null);

    if (ecPolicyState == null && !ecPolicyName.equals(REPLICATION_POLICY_NAME)) {
      throw new ActionException("The EC policy " + ecPolicyName + " is not supported!");
    } else if (ecPolicyState == ErasureCodingPolicyState.DISABLED
        || ecPolicyState == ErasureCodingPolicyState.REMOVED) {
      throw new ActionException("The EC policy " + ecPolicyName + " is disabled or removed!");
    }
  }

  @Override
  public FsType localFsType() {
    return FsType.DEFAULT_HDFS;
  }
}