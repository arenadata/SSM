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
import org.smartdata.model.BackUpInfo;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoUpdate;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Collectors;
import org.smartdata.model.PathChecker;

/**
 * This is a very preliminary and buggy applier, can further enhance by referring to
 * {@link org.apache.hadoop.hdfs.server.namenode.FSEditLogLoader}
 */
public class InotifyEventApplier {
  private static final String ROOT_DIRECTORY = "/";

  private final MetaStore metaStore;
  private final PathChecker pathChecker;
  private DFSClient client;
  private static final Logger LOG =
      LoggerFactory.getLogger(InotifyEventFetcher.class);
  private NamespaceFetcher namespaceFetcher;

  public InotifyEventApplier(MetaStore metaStore, DFSClient client) {
    this(new SmartConf(), metaStore, client);
  }

  public InotifyEventApplier(SmartConf conf, MetaStore metaStore, DFSClient client, NamespaceFetcher namespaceFetcher) {
    this(conf, metaStore, client);
    this.namespaceFetcher = namespaceFetcher;
  }

  public InotifyEventApplier(SmartConf conf, MetaStore metaStore, DFSClient client) {
    this.metaStore = metaStore;
    this.client = client;
    this.pathChecker = new PathChecker(conf);
  }

  public void apply(List<Event> events) throws IOException, MetaStoreException, InterruptedException {
    for (Event event : events) {
      apply(event);
    }
  }

  public void apply(Event[] events) throws IOException, MetaStoreException, InterruptedException {
    this.apply(Arrays.asList(events));
  }

  private void apply(Event event) throws IOException, MetaStoreException, InterruptedException {
    String path;
    String srcPath, dstPath;
    LOG.debug("Even Type = {}", event.getEventType());

    // we already filtered events in the fetch tasks, so we can skip
    // event's path check here
    switch (event.getEventType()) {
      case CREATE:
        path = ((Event.CreateEvent) event).getPath();
        LOG.trace("event type: {}, path: {}", event.getEventType().name(), path);
        applyCreate((Event.CreateEvent) event);
        break;
      case CLOSE:
        path = ((Event.CloseEvent) event).getPath();
        LOG.trace("event type: {}, path: {}", event.getEventType().name(), path);
        applyClose((Event.CloseEvent) event);
        break;
      case RENAME:
        srcPath = ((Event.RenameEvent) event).getSrcPath();
        dstPath = ((Event.RenameEvent) event).getDstPath();
        LOG.trace("event type: {}, src path: {}, dest path: {}",
            event.getEventType().name(), srcPath, dstPath);
        applyRename((Event.RenameEvent)event);
        break;
      case METADATA:
        // The property dfs.namenode.accesstime.precision in HDFS's configuration controls
        // the precision of access time. Its default value is 1h. To avoid missing a
        // MetadataUpdateEvent for updating access time, a smaller value should be set.
        path = ((Event.MetadataUpdateEvent)event).getPath();
        LOG.trace("event type: {}, path: {}", event.getEventType().name(), path);
        applyMetadataUpdate((Event.MetadataUpdateEvent)event);
        break;
      case APPEND:
        path = ((Event.AppendEvent)event).getPath();
        LOG.trace("event type: {}, path: {}", event.getEventType().name(), path);
        // do nothing
        break;
      case UNLINK:
        path = ((Event.UnlinkEvent)event).getPath();
        LOG.trace("event type: {}, path: {}", event.getEventType().name(), path);
        applyUnlink((Event.UnlinkEvent)event);
    }
  }

  //Todo: times and ec policy id, etc.
  private void applyCreate(Event.CreateEvent createEvent) throws IOException, MetaStoreException {
    FileInfo fileInfo = getFileInfo(createEvent.getPath());
    if (fileInfo == null) {
      return;
    }

    applyCreateFileDiff(fileInfo);
    metaStore.deleteFileByPath(fileInfo.getPath(), false);
    metaStore.deleteFileState(fileInfo.getPath());
    metaStore.insertFile(fileInfo);
  }

  private void applyRenameIgnoredFile(Event.RenameEvent renameEvent) throws IOException, MetaStoreException {
    FileInfo fileInfo = getFileInfo(renameEvent.getDstPath());
    if (fileInfo == null) {
      return;
    }

    applyCreateFileDiff(fileInfo);
    metaStore.deleteFileByPath(fileInfo.getPath(), false);
    metaStore.insertFile(fileInfo);
    metaStore.renameFile(renameEvent.getSrcPath(), renameEvent.getDstPath(), fileInfo.isdir());
  }

  private FileInfo getFileInfo(String path) throws IOException {
    HdfsFileStatus fileStatus = client.getFileInfo(path);
    if (fileStatus == null) {
      LOG.debug("Can not get HdfsFileStatus for file " + path);
      return null;
    }

    return HadoopUtil.convertFileStatus(fileStatus, path);
  }

  private void applyCreateFileDiff(FileInfo fileInfo) throws MetaStoreException {
    if (inBackup(fileInfo.getPath())) {
      if (!fileInfo.isdir()) {

        // ignore dir
        FileDiff fileDiff = new FileDiff(FileDiffType.APPEND);
        fileDiff.setSrc(fileInfo.getPath());
        fileDiff.getParameters().put("-offset", String.valueOf(0));
        // Note that "-length 0" means create an empty file
        fileDiff.getParameters()
            .put("-length", String.valueOf(fileInfo.getLength()));
        // TODO add support in CopyFileAction or split into two file diffs
        //add modification_time and access_time to filediff
        fileDiff.getParameters().put("-mtime", "" + fileInfo.getModificationTime());
        // fileDiff.getParameters().put("-atime", "" + fileInfo.getAccessTime());
        //add owner to filediff
        fileDiff.getParameters().put("-owner", "" + fileInfo.getOwner());
        fileDiff.getParameters().put("-group", "" + fileInfo.getGroup());
        //add Permission to filediff
        fileDiff.getParameters().put("-permission", "" + fileInfo.getPermission());
        //add replication count to file diff
        fileDiff.getParameters().put("-replication", "" + fileInfo.getBlockReplication());
        metaStore.insertFileDiff(fileDiff);
      }
    }
  }

  private boolean inBackup(String src) throws MetaStoreException {
    return metaStore.srcInBackup(src);
  }

  //Todo: should update mtime? atime?
  private void applyClose(Event.CloseEvent closeEvent) throws MetaStoreException {
    FileDiff fileDiff = new FileDiff(FileDiffType.APPEND);
    fileDiff.setSrc(closeEvent.getPath());
    long newLen = closeEvent.getFileSize();
    long currLen;
    // TODO make sure offset is correct
    if (inBackup(closeEvent.getPath())) {
      FileInfo fileInfo = metaStore.getFile(closeEvent.getPath());
      if (fileInfo == null) {
        // TODO add metadata
        currLen = 0;
      } else {
        currLen = fileInfo.getLength();
      }
      if (currLen != newLen) {
        fileDiff.getParameters().put("-offset", String.valueOf(currLen));
        fileDiff.getParameters()
            .put("-length", String.valueOf(newLen - currLen));
        metaStore.insertFileDiff(fileDiff);
      }
    }
    FileInfoUpdate fileInfoUpdate = new FileInfoUpdate()
        .setLength(closeEvent.getFileSize())
        .setModificationTime(closeEvent.getTimestamp());
    metaStore.updateFileByPath(closeEvent.getPath(), fileInfoUpdate);
  }

  //Todo: should update mtime? atime?
//  private String getTruncateSql(Event.TruncateEvent truncateEvent) {
//    return String.format(
//        "UPDATE file SET length = %s, modification_time = %s WHERE path = '%s';",
//        truncateEvent.getFileSize(), truncateEvent.getTimestamp(), truncateEvent.getPath());
//  }

  private void applyRename(Event.RenameEvent renameEvent)
      throws IOException, MetaStoreException, InterruptedException {
    String src = renameEvent.getSrcPath();
    String dest = renameEvent.getDstPath();

    if (pathChecker.isIgnored(src)) {
      applyRenameIgnoredFile(renameEvent);
      return;
    }

    HdfsFileStatus status = client.getFileInfo(dest);
    FileInfo info = metaStore.getFile(src);

    // For backup data to use.
    generateFileDiff(renameEvent);

    if (status == null) {
      LOG.debug("Get rename dest status failed, {} -> {}", src, dest);
    }
    // The dest path which the src is renamed to should be checked in file table
    // to avoid duplicated record for one same path.
    FileInfo destInfo = metaStore.getFile(dest);
    if (destInfo != null) {
      metaStore.deleteFileByPath(dest, false);
    }
    // src is not in file table because it is not fetched or other reason
    if (info == null) {
      if (status != null) {
        //info = HadoopUtil.convertFileStatus(status, dest);
        //metaStore.insertFile(info);
        namespaceFetcher.startFetch(dest);
        while(!namespaceFetcher.fetchFinished()) {
          LOG.info("Fetching the files under " + dest);
          Thread.sleep(100);
        }
        namespaceFetcher.stop();
      }
      return;
    }

    // if the dest is ignored, delete src info from file table
    // TODO: tackle with file_state and small_state
    if (pathChecker.isIgnored(dest)) {
      // fuzzy matching is used to delete content under the dir
      metaStore.deleteFileByPath(src, true);
      return;
    }

    metaStore.renameFile(src, dest, info.isdir());
  }

  private void generateFileDiff(Event.RenameEvent renameEvent)
      throws MetaStoreException {
    String src = renameEvent.getSrcPath();
    String dest = renameEvent.getDstPath();
    FileInfo info = metaStore.getFile(src);
    // TODO: consider src or dest is ignored by SSM
    if (inBackup(src)) {
      // rename the file if the renamed file is still under the backup src dir
      // if not, insert a delete file diff
      if (inBackup(dest)) {
        FileDiff fileDiff = new FileDiff(FileDiffType.RENAME);
        fileDiff.setSrc(src);
        fileDiff.getParameters().put("-dest", dest);
        metaStore.insertFileDiff(fileDiff);
      } else {
        insertDeleteDiff(src, info.isdir());
      }
    } else if (inBackup(dest)) {
      // tackle such case: rename file from outside into backup dir
      if (!info.isdir()) {
        FileDiff fileDiff = new FileDiff(FileDiffType.APPEND);
        fileDiff.setSrc(dest);
        fileDiff.getParameters().put("-offset", String.valueOf(0));
        fileDiff.getParameters()
            .put("-length", String.valueOf(info.getLength()));
        metaStore.insertFileDiff(fileDiff);
      } else {
        List<FileInfo> fileInfos = metaStore.getFilesByPrefix(src.endsWith("/") ? src : src + "/");
        for (FileInfo fileInfo : fileInfos) {
          // TODO: cover subdir with no file case
          if (fileInfo.isdir()) {
            continue;
          }
          FileDiff fileDiff = new FileDiff(FileDiffType.APPEND);
          fileDiff.setSrc(fileInfo.getPath().replaceFirst(src, dest));
          fileDiff.getParameters().put("-offset", String.valueOf(0));
          fileDiff.getParameters()
              .put("-length", String.valueOf(fileInfo.getLength()));
          metaStore.insertFileDiff(fileDiff);
        }
      }
    }
  }

  private void applyMetadataUpdate(Event.MetadataUpdateEvent metadataUpdateEvent) throws MetaStoreException {

    FileDiff fileDiff = null;
    if (inBackup(metadataUpdateEvent.getPath())) {
      fileDiff = new FileDiff(FileDiffType.METADATA);
      fileDiff.setSrc(metadataUpdateEvent.getPath());
    }
    FileInfoUpdate fileInfoUpdate = new FileInfoUpdate();
    switch (metadataUpdateEvent.getMetadataType()) {
      case TIMES:
        if (metadataUpdateEvent.getMtime() > 0) {
          if (fileDiff != null) {
            fileDiff.getParameters().put("-mtime", String.valueOf(metadataUpdateEvent.getMtime()));
            // fileDiff.getParameters().put("-access_time", "" + metadataUpdateEvent.getAtime());
            metaStore.insertFileDiff(fileDiff);
          }
          fileInfoUpdate.setModificationTime(metadataUpdateEvent.getMtime());
        }
        if (metadataUpdateEvent.getAtime() > 0) {
          // if (fileDiff != null) {
          //   fileDiff.getParameters().put("-access_time", "" + metadataUpdateEvent.getAtime());
          //   metaStore.insertFileDiff(fileDiff);
          // }
          fileInfoUpdate.setAccessTime(metadataUpdateEvent.getAtime());
        }
        break;
      case OWNER:
        if (fileDiff != null) {
          fileDiff.getParameters().put("-owner", metadataUpdateEvent.getOwnerName());
          metaStore.insertFileDiff(fileDiff);
        }
        fileInfoUpdate.setOwner(metadataUpdateEvent.getOwnerName())
            .setGroup(metadataUpdateEvent.getGroupName());
        break;
      case PERMS:
        if (fileDiff != null) {
          fileDiff.getParameters().put("-permission", "" + metadataUpdateEvent.getPerms().toShort());
          metaStore.insertFileDiff(fileDiff);
        }
        fileInfoUpdate.setPermission(metadataUpdateEvent.getPerms().toShort());
        break;
      case REPLICATION:
        if (fileDiff != null) {
          fileDiff.getParameters().put("-replication", "" + metadataUpdateEvent.getReplication());
          metaStore.insertFileDiff(fileDiff);
        }
        fileInfoUpdate.setBlockReplication((short) metadataUpdateEvent.getReplication());
        break;
      case XATTRS:
        final String EC_POLICY = "hdfs.erasurecoding.policy";
        //Todo
        if (LOG.isDebugEnabled()) {
          String message = metadataUpdateEvent.getxAttrs()
              .stream()
              .map(XAttr::toString)
              .collect(Collectors.joining("\n"));
          LOG.debug(message);
        }
        // The following code should be executed merely on HDFS3.x.
        for (XAttr xAttr : metadataUpdateEvent.getxAttrs()) {
          if (xAttr.getName().equals(EC_POLICY)) {
            try {
              String ecPolicyName = WritableUtils.readString(
                  new DataInputStream(new ByteArrayInputStream(xAttr.getValue())));
              byte ecPolicyId = CompatibilityHelperLoader.getHelper().
                  getErasureCodingPolicyByName(client, ecPolicyName);
              if (ecPolicyId == (byte) -1) {
                LOG.error("Unrecognized EC policy for updating!");
              }
              fileInfoUpdate.setErasureCodingPolicy(ecPolicyId);
              break;
            } catch (IOException ex) {
              LOG.error("Error occurred for updating ecPolicy!", ex);
            }
          }
        }
        break;
      case ACLS:
        return;
    }
    metaStore.updateFileByPath(metadataUpdateEvent.getPath(), fileInfoUpdate);
  }

  private void applyUnlink(Event.UnlinkEvent unlinkEvent) throws MetaStoreException {
    // delete root, i.e., /
    if (ROOT_DIRECTORY.equals(unlinkEvent.getPath())) {
      LOG.warn("Deleting root directory!!!");
      insertDeleteDiff(ROOT_DIRECTORY, true);
      metaStore.unlinkRootDirectory();
      return;
    }

    String path = unlinkEvent.getPath();
    // file has no "/" appended in the metaStore
    FileInfo fileInfo = metaStore.getFile(path.endsWith("/") ?
        path.substring(0, path.length() - 1) : path);

    if (fileInfo != null) {
      insertDeleteDiff(unlinkEvent.getPath(), fileInfo.isdir());
      metaStore.unlinkFile(unlinkEvent.getPath(), fileInfo.isdir());
    }
  }

  // TODO: just insert a fileDiff for this kind of path.
  // It seems that there is no need to see if path matches with one dir in FileInfo.
  private void insertDeleteDiff(String path, boolean isDir) throws MetaStoreException {
    if (isDir) {
      path = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
      List<FileInfo> fileInfos = metaStore.getFilesByPrefix(path);
      for (FileInfo fileInfo : fileInfos) {
        if (fileInfo.isdir()) {
          if (path.equals(fileInfo.getPath())) {
            insertDeleteDiff(fileInfo.getPath());
            break;
          }
        }
      }
    } else {
      insertDeleteDiff(path);
    }
  }

  private void insertDeleteDiff(String path) throws MetaStoreException {
    // TODO: remove "/" appended in src or dest in backup_file table
    String pathWithSlash = path.endsWith("/") ? path : path + "/";
    if (inBackup(path)) {
      List<BackUpInfo> backUpInfos = metaStore.getBackUpInfoBySrc(pathWithSlash);
      for (BackUpInfo backUpInfo : backUpInfos) {
        String destPath = pathWithSlash.replaceFirst(backUpInfo.getSrc(), backUpInfo.getDest());
        try {
          // tackle root path case
          URI namenodeUri = new URI(destPath);
          String root = "hdfs://" + namenodeUri.getHost() + ":"
              + String.valueOf(namenodeUri.getPort());
          if (destPath.equals(root) || destPath.equals(root + "/") || destPath.equals("/")) {
            for (String srcFilePath : getFilesUnderDir(pathWithSlash)) {
              FileDiff fileDiff = new FileDiff(FileDiffType.DELETE);
              fileDiff.setSrc(srcFilePath);
              String destFilePath = srcFilePath.replaceFirst(backUpInfo.getSrc(), backUpInfo.getDest());
              fileDiff.getParameters().put("-dest", destFilePath);
              metaStore.insertFileDiff(fileDiff);
            }
          } else {
            FileDiff fileDiff = new FileDiff(FileDiffType.DELETE);
            // use the path getting from event with no slash appended
            fileDiff.setSrc(path);
            // put sync's dest path in parameter for delete use
            fileDiff.getParameters().put("-dest", destPath);
            metaStore.insertFileDiff(fileDiff);
          }
        } catch (URISyntaxException e) {
          LOG.error("Error occurs!", e);
        }
      }
    }
  }

  private List<String> getFilesUnderDir(String dir) throws MetaStoreException {
    dir = dir.endsWith("/") ? dir : dir + "/";
    List<String> fileList = new ArrayList<>();
    List<String> subdirList = new ArrayList<>();
    // get fileInfo in asc order of path to guarantee that
    // the subdir is tackled prior to files or dirs under it
    List<FileInfo> fileInfos = metaStore.getFilesByPrefixInOrder(dir);
    for (FileInfo fileInfo : fileInfos) {
      // just delete subdir instead of deleting all files under it
      if (isUnderDir(fileInfo.getPath(), subdirList)) {
        continue;
      }
      fileList.add(fileInfo.getPath());
      if (fileInfo.isdir()) {
        subdirList.add(fileInfo.getPath());
      }
    }
    return fileList;
  }

  private boolean isUnderDir(String path, List<String> dirs) {
    if (dirs.isEmpty()) {
      return false;
    }
    for (String subdir : dirs) {
      if (path.startsWith(subdir)) {
        return true;
      }
    }
    return false;
  }
}
