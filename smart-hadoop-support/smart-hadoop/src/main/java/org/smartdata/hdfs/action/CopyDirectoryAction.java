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
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.ActionException;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.GROUP;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.OWNER;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.PERMISSIONS;

/**
 * An action to copy a directory without content
 * If dest doesn't contain "hdfs" prefix, then destination will be set to
 * current cluster, i.e., mkdir in current cluster.
 */
@ActionSignature(
    actionId = "dircopy",
    displayName = "dircopy",
    usage = HdfsAction.FILE_PATH + " $file"
)
public class CopyDirectoryAction extends CopyPreservedAttributesAction {
  public static final String DEST_PATH = "-dest";

  private Path srcPath;
  private Path destPath;

  public static final Set<PreserveAttribute> SUPPORTED_PRESERVE_ATTRIBUTES
      = Sets.newHashSet(OWNER, GROUP, PERMISSIONS);

  public CopyDirectoryAction() {
    super(SUPPORTED_PRESERVE_ATTRIBUTES, SUPPORTED_PRESERVE_ATTRIBUTES);
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = getPathArg(FILE_PATH);
    this.destPath = getPathArg(DEST_PATH);
  }

  @Override
  protected void execute() throws Exception {
    validateArgs();
    Set<PreserveAttribute> preserveAttributes = parsePreserveAttributes();

    FileSystem destFileSystem = getFileSystemFor(destPath);
    createTargetDirectory(destFileSystem);

    copyFileAttributes(
        getFileSystemFor(srcPath).getFileStatus(srcPath),
        destPath,
        destFileSystem,
        preserveAttributes);

    appendLog("Copy directory success!");
  }

  private void validateArgs() throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST_PATH);
    if (!localFileSystem.exists(srcPath)) {
      throw new ActionException("Src directory doesn't exist:" + srcPath);
    }
  }

  private void createTargetDirectory(FileSystem destFileSystem) throws IOException {
    appendLog(
        String.format("Creating directory %s", destPath));
    destFileSystem.mkdirs(destPath);
  }
}
