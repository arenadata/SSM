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

import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.smartdata.action.SmartAction;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.CmdletDescriptor;

import java.io.IOException;
import java.util.Optional;

import static org.smartdata.utils.PathUtil.getRemoteFileSystem;
import static org.smartdata.utils.PathUtil.isAbsoluteRemotePath;


/**
 * Base class for all HDFS actions.
 */
@Setter
public abstract class HdfsAction extends SmartAction {
  public static final String FILE_PATH = CmdletDescriptor.HDFS_FILE_PATH;

  protected DistributedFileSystem localFileSystem;

  public enum FsType {
    SMART,
    DEFAULT_HDFS
  }

  public FsType localFsType() {
    return FsType.SMART;
  }

  @Override
  protected void preRun() throws Exception {
    super.preRun();
    withDefaultFs();
  }

  protected DFSClient getLocalDfsClient() {
    return Optional.ofNullable(localFileSystem)
        .map(DistributedFileSystem::getClient)
        .orElse(null);
  }

  protected void withDefaultFs() {
    Configuration conf = getContext().getConf();
    String nameNodeURL = conf.get(SmartConfKeys.SMART_DFS_NAMENODE_RPCSERVER_KEY);
    conf.set(DFSConfigKeys.FS_DEFAULT_NAME_KEY, nameNodeURL);
  }

  protected void validateNonEmptyArgs(String... keys) {
    for (String key : keys) {
      validateNonEmptyArg(key);
    }
  }

  protected void validateNonEmptyArg(String key) {
    if (StringUtils.isBlank(getArguments().get(key))) {
      throw new IllegalArgumentException(key + " parameter is missing.");
    }
  }

  protected SmartConf getConf() {
    return getContext().getConf();
  }

  protected Path getPathArg(String key) {
    return Optional.ofNullable(getArguments().get(key))
        .filter(StringUtils::isNotBlank)
        .map(Path::new)
        .orElse(null);
  }

  protected FileSystem getFileSystemFor(Path path) throws IOException {
    return isAbsoluteRemotePath(path)
        ? getRemoteFileSystem(path, getConf())
        : localFileSystem;
  }

  protected boolean isArgPresent(String key) {
    return StringUtils.isNotBlank(getArguments().get(key));
  }

  protected Optional<FileStatus> getFileStatus(FileSystem fileSystem, Path path) throws IOException {
    try {
      return Optional.of(fileSystem.getFileStatus(path));
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  protected Optional<HdfsFileStatus> getHdfsFileStatus(FileSystem fileSystem, Path path) throws IOException {
    return getFileStatus(fileSystem, path).map(HdfsFileStatus.class::cast);
  }
}
