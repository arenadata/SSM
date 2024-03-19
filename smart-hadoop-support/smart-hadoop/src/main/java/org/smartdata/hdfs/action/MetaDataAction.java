/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.hdfs.action;

import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.model.FileInfoDiff;

/**
 * action to set MetaData of file
 */
@ActionSignature(
    actionId = "metadata",
    displayName = "metadata",
    usage = HdfsAction.FILE_PATH + " $src " + MetaDataAction.OWNER_NAME + " $owner " +
        MetaDataAction.GROUP_NAME + " $group " + MetaDataAction.BLOCK_REPLICATION + " $replication " +
        MetaDataAction.PERMISSION + " $permission " + MetaDataAction.MTIME + " $mtime " +
        MetaDataAction.ATIME + " $atime"
)
public class MetaDataAction extends HdfsAction {
  public static final String OWNER_NAME = "-owner";
  public static final String GROUP_NAME = "-group";
  public static final String BLOCK_REPLICATION = "-replication";
  // only support input like 777
  public static final String PERMISSION = "-permission";
  public static final String MTIME = "-mtime";
  public static final String ATIME = "-atime";

  private FileInfoDiff fileInfoDiff;

  private UpdateFileMetadataSupport delegate;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);

    fileInfoDiff = new FileInfoDiff()
        .setPath(args.get(FILE_PATH))
        .setOwner(args.get(OWNER_NAME))
        .setGroup(args.get(GROUP_NAME))
        .setModificationTime(NumberUtils.createLong(args.get(MTIME)))
        .setAccessTime(NumberUtils.createLong(args.get(ATIME)));

    if (args.containsKey(BLOCK_REPLICATION)) {
      fileInfoDiff.setBlockReplication(Short.parseShort(args.get(BLOCK_REPLICATION)));
    }

    if (args.containsKey(PERMISSION)) {
      fileInfoDiff.setPermission(Short.parseShort(args.get(PERMISSION)));
    }

    delegate = new UpdateFileMetadataSupport(
        getContext().getConf(), getLogPrintStream());
  }

  @Override
  protected void execute() throws Exception {
    if (StringUtils.isBlank(fileInfoDiff.getPath())) {
      throw new IllegalArgumentException("File src is missing.");
    }

    delegate.changeFileMetadata(fileInfoDiff);
  }
}
