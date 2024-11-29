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
package org.smartdata.hdfs.metric.fetcher;

import org.apache.hadoop.fs.XAttr;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.inotify.Event;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.apache.hadoop.io.WritableUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.hdfs.CompatibilityHelperLoader;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoDiff;
import org.smartdata.model.PathChecker;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * This is a very preliminary and buggy applier, can further enhance by referring to
 * {@link org.apache.hadoop.hdfs.server.namenode.FSEditLogLoader}
 */
public class InotifyEventApplier {
  private static final Logger LOG =
      LoggerFactory.getLogger(InotifyEventApplier.class);

  private static final String ROOT_DIRECTORY = "/";
  private static final String EC_POLICY_XATTR = "hdfs.erasurecoding.policy";

  private static final byte DEFAULT_STORAGE_POLICY_ID = 7;
  private static final byte DEFAULT_EC_POLICY_ID = 0;

  private final MetaStore metaStore;
  private final PathChecker pathChecker;
  private final DFSClient client;
  private final FileDiffGenerator fileDiffGenerator;

  public InotifyEventApplier(SmartConf conf, MetaStore metaStore, DFSClient client) {
    this(conf, metaStore, client, new FileDiffGenerator(metaStore, System::currentTimeMillis));
  }

  public InotifyEventApplier(SmartConf conf, MetaStore metaStore,
      DFSClient client, FileDiffGenerator fileDiffGenerator) {
    this.metaStore = metaStore;
    this.client = client;
    this.pathChecker = new PathChecker(conf);
    this.fileDiffGenerator = fileDiffGenerator;
  }

  public void apply(List<Event> events) throws IOException, InterruptedException {
    for (Event event : events) {
      apply(event);
    }
  }

  public void apply(Event[] events) throws IOException, InterruptedException {
    apply(Arrays.asList(events));
  }

  private void apply(Event event) throws IOException {
    LOG.debug("Handle INotify event: {}", event);

    // we already filtered events in the fetch tasks, so we can skip
    // event's path check here
    switch (event.getEventType()) {
      case CREATE:
        applyCreate((Event.CreateEvent) event);
        break;
      case CLOSE:
        applyClose((Event.CloseEvent) event);
        break;
      case RENAME:
        applyRename((Event.RenameEvent) event);
        break;
      case METADATA:
        // The property dfs.namenode.accesstime.precision in HDFS's configuration controls
        // the precision of access time. Its default value is 1h. To avoid missing a
        // MetadataUpdateEvent for updating access time, a smaller value should be set.
        applyMetadataUpdate((Event.MetadataUpdateEvent) event);
        break;
      case UNLINK:
        applyUnlink((Event.UnlinkEvent) event);
      case APPEND:
        break;
    }
  }

  private void applyCreate(Event.CreateEvent createEvent) throws IOException {
    FileInfo fileInfo = fileBuilderWithPolicies(createEvent.getPath())
        .setPath(createEvent.getPath())
        .setIsDir(createEvent.getiNodeType() == Event.CreateEvent.INodeType.DIRECTORY)
        .setBlockReplication((short) createEvent.getReplication())
        .setBlockSize(createEvent.getDefaultBlockSize())
        .setModificationTime(createEvent.getCtime())
        .setAccessTime(createEvent.getCtime())
        .setPermission(createEvent.getPerms().toShort())
        .setOwner(createEvent.getOwnerName())
        .setGroup(createEvent.getGroupName())
        .build();

    fileDiffGenerator.onFileCreate(fileInfo)
        .ifPresent(this::insertFileDiffUnchecked);

    metaStore.deleteFileByPath(fileInfo.getPath(), false);
    metaStore.deleteFileState(fileInfo.getPath());
    metaStore.insertFile(fileInfo, true);
  }

  private Optional<HdfsFileStatus> getHdfsFileStatus(String path) throws IOException {
    return Optional.ofNullable(client.getFileInfo(path));
  }

  private void insertFileDiffUnchecked(FileDiff fileDiff) {
    try {
      metaStore.insertFileDiff(fileDiff);
    } catch (MetaStoreException e) {
      throw new UncheckedIOException(e);
    }
  }

  // TODO store ignored files to metastore as well
  // to take info from metastore instead of fetching fileInfo from hdfs
  private void applyRenameIgnoredFile(Event.RenameEvent renameEvent) throws IOException {
    FileInfo fileInfo = getFileInfo(renameEvent.getDstPath());
    if (fileInfo == null) {
      LOG.warn("Error getting info about file moved from ignored directory {}",
          renameEvent.getDstPath());
      return;
    }

    fileDiffGenerator.onFileCreate(fileInfo)
        .ifPresent(this::insertFileDiffUnchecked);

    metaStore.deleteFileByPath(fileInfo.getPath(), false);
    metaStore.insertFile(fileInfo, true);
    metaStore.renameFile(renameEvent.getSrcPath(), renameEvent.getDstPath(), fileInfo.isDir());
  }

  private FileInfo getFileInfo(String path) throws IOException {
    return getHdfsFileStatus(path)
        .map(status -> HadoopUtil.convertFileStatus(status, path))
        .orElseGet(() -> {
          LOG.warn("Error getting file status for file {}", path);
          return null;
        });
  }

  //Todo: should update mtime? atime?
  private void applyClose(Event.CloseEvent closeEvent) throws MetaStoreException {
    fileDiffGenerator.onFileClose(closeEvent)
        .ifPresent(this::insertFileDiffUnchecked);

    FileInfoDiff fileInfoDiff = new FileInfoDiff()
        .setLength(closeEvent.getFileSize())
        .setModificationTime(closeEvent.getTimestamp());
    metaStore.updateFileByPath(closeEvent.getPath(), fileInfoDiff);
  }

  private void applyRename(Event.RenameEvent renameEvent) throws IOException {
    String src = renameEvent.getSrcPath();
    String dest = renameEvent.getDstPath();

    // if the src is ignored, create new file with dest path
    if (pathChecker.isIgnored(src)) {
      applyRenameIgnoredFile(renameEvent);
      return;
    }

    // if the dest is ignored, delete src info from file table
    if (pathChecker.isIgnored(dest)) {
      deleteFile(src);
      return;
    }

    FileInfo srcFile = metaStore.getFile(src);
    if (srcFile == null) {
      LOG.error(
          "Inconsistency in metastore and HDFS namespace, file not found: {}",
          renameEvent.getSrcPath());
      return;
    }

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(renameEvent, srcFile);
    metaStore.insertFileDiffs(fileDiffs);

    // The dest path which the src is renamed to should be checked in file table
    // to avoid duplicated record for one same path.
    FileInfo destInfo = metaStore.getFile(dest);
    if (destInfo != null) {
      metaStore.deleteFileByPath(dest, false);
    }

    metaStore.renameFile(src, dest, srcFile.isDir());
    maybeSetPolicies(srcFile, dest);
  }

  private void applyMetadataUpdate(
      Event.MetadataUpdateEvent metadataUpdateEvent) throws MetaStoreException {
    fileDiffGenerator.onMetadataUpdate(metadataUpdateEvent)
        .ifPresent(this::insertFileDiffUnchecked);

    FileInfoDiff fileInfoUpdate = new FileInfoDiff();
    switch (metadataUpdateEvent.getMetadataType()) {
      case TIMES:
        if (metadataUpdateEvent.getMtime() > 0) {
          fileInfoUpdate.setModificationTime(metadataUpdateEvent.getMtime());
        }
        if (metadataUpdateEvent.getAtime() > 0) {
          fileInfoUpdate.setAccessTime(metadataUpdateEvent.getAtime());
        }
        break;
      case OWNER:
        fileInfoUpdate.setOwner(metadataUpdateEvent.getOwnerName())
            .setGroup(metadataUpdateEvent.getGroupName());
        break;
      case PERMS:
        fileInfoUpdate.setPermission(metadataUpdateEvent.getPerms().toShort());
        break;
      case REPLICATION:
        fileInfoUpdate.setBlockReplication((short) metadataUpdateEvent.getReplication());
        break;
      case XATTRS:
        getErasureCodingPolicyId(metadataUpdateEvent.getxAttrs())
            .ifPresent(fileInfoUpdate::setErasureCodingPolicy);
        break;
      case ACLS:
        return;
    }
    metaStore.updateFileByPath(metadataUpdateEvent.getPath(), fileInfoUpdate);
  }

  private void applyUnlink(Event.UnlinkEvent unlinkEvent) throws MetaStoreException {
    deleteFile(unlinkEvent.getPath());
  }

  private void deleteFile(String path) throws MetaStoreException {
    fileDiffGenerator.onFileDelete(path)
        .ifPresent(this::insertFileDiffUnchecked);

    // delete root, i.e., /
    if (ROOT_DIRECTORY.equals(path)) {
      LOG.warn("Deleting root directory!!!");
      metaStore.unlinkRootDirectory();
      return;
    }

    // file has no "/" appended in the metaStore
    FileInfo fileInfo = metaStore.getFile(path.endsWith("/") ?
        path.substring(0, path.length() - 1) : path);

    if (fileInfo != null) {
      metaStore.unlinkFile(path, fileInfo.isDir());
    }
  }

  private Optional<Byte> getErasureCodingPolicyId(List<XAttr> xAttrs) {
    for (XAttr xAttr : xAttrs) {
      if (!EC_POLICY_XATTR.equals(xAttr.getName())) {
        continue;
      }

      try {
        String ecPolicyName = WritableUtils.readString(
            new DataInputStream(new ByteArrayInputStream(xAttr.getValue())));
        byte ecPolicyId = CompatibilityHelperLoader.getHelper().
            getErasureCodingPolicyByName(client, ecPolicyName);
        if (ecPolicyId == (byte) -1) {
          LOG.error("Unrecognized EC policy for updating: {}", ecPolicyId);
        }
        return Optional.of(ecPolicyId);
      } catch (IOException ex) {
        LOG.error("Error occurred for updating ecPolicy!", ex);
      }
    }

    return Optional.empty();
  }


  /** @see InotifyEventApplier#fileBuilderWithPolicies */
  private void maybeSetPolicies(FileInfo oldFile, String newPath) throws IOException {
    if (oldFile.getErasureCodingPolicy() != DEFAULT_EC_POLICY_ID
        || oldFile.getStoragePolicy() != DEFAULT_STORAGE_POLICY_ID) {
      // we don't need to update anything in case if policies were
      // already applied during create event handling
      return;
    }

    Optional<HdfsFileStatus> fileStatus = getHdfsFileStatus(newPath);
    if (!fileStatus.isPresent()) {
      LOG.warn("Error getting status for {} after rename", newPath);
      return;
    }

    FileInfoDiff fileInfoDiff = new FileInfoDiff()
        .setStoragePolicy(fileStatus.get().getStoragePolicy())
        .setErasureCodingPolicy(CompatibilityHelperLoader.getHelper()
            .getErasureCodingPolicy(fileStatus.get()));
    metaStore.updateFileByPath(newPath, fileInfoDiff);
  }

  /**
   * Try to enrich FileInfo builder with EC and storage policies
   * information from HDFS. In case if no information is found in HDFS for
   * specified file, fallback to default policies.
   *
   * HDFS client will return null information about file in 2 cases:
   * it was either deleted or renamed. In first case, there will be no issue,
   * if we use fallback policies, because SSM will eventually remove file from its
   * namespace copy, when the delete event arrive.
   * In case of rename we will try to fetch policies info from HDFS again
   * for the new name in the {@link InotifyEventApplier#maybeSetPolicies}.
   * In case of failure in this method too, it only means, that file was deleted after rename.
   */
  private FileInfo.Builder fileBuilderWithPolicies(String path) {
    try {
      return getHdfsFileStatus(path)
          .map(status -> FileInfo.builder()
              .setStoragePolicy(status.getStoragePolicy())
              .setErasureCodingPolicy(
                  CompatibilityHelperLoader.getHelper().getErasureCodingPolicy(status)))
          .orElseGet(() -> {
            LOG.warn("Can't enrich info about new file: {} not found", path);
            return defaultFileBuilder();
          });
    } catch (IOException e) {
      LOG.warn("Can't enrich info about new file: {}", path, e);
      return defaultFileBuilder();
    }
  }

  private FileInfo.Builder defaultFileBuilder() {
    return FileInfo.builder()
        .setStoragePolicy(DEFAULT_STORAGE_POLICY_ID)
        .setErasureCodingPolicy(DEFAULT_EC_POLICY_ID);
  }
}
