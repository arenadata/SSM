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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hdfs.inotify.Event;
import org.smartdata.action.SyncAction;
import org.smartdata.hdfs.action.CopyFileAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffState;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.FileInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import static org.smartdata.action.SyncAction.BASE_OPERATION;
import static org.smartdata.hdfs.action.MetaDataAction.BLOCK_REPLICATION;
import static org.smartdata.hdfs.action.MetaDataAction.GROUP_NAME;
import static org.smartdata.hdfs.action.MetaDataAction.MTIME;
import static org.smartdata.hdfs.action.MetaDataAction.OWNER_NAME;
import static org.smartdata.hdfs.action.MetaDataAction.PERMISSION;
import static org.smartdata.utils.PathUtil.addPathSeparator;

@Slf4j
@RequiredArgsConstructor
public class FileDiffGenerator {

  private final MetaStore metaStore;
  private final Supplier<Long> currentTimeMsSupplier;

  public Optional<FileDiff> onFileCreate(FileInfo file) throws MetaStoreException {
    if (!inBackup(file.getPath())) {
      return Optional.empty();
    }

    FileDiff createDiff = toCreateDiff(file, file.getPath());
    return Optional.of(createDiff);
  }

  public Optional<FileDiff> onFileClose(Event.CloseEvent closeEvent) throws MetaStoreException {
    if (!inBackup(closeEvent.getPath())) {
      return Optional.empty();
    }

    FileInfo fileInfo = metaStore.getFile(closeEvent.getPath());
    long currentLength = Optional.ofNullable(fileInfo)
        .map(FileInfo::getLength)
        .orElse(0L);

    if (currentLength == closeEvent.getFileSize()) {
      return Optional.empty();
    }

    FileDiff fileDiff = toAppendDiff(closeEvent.getPath(), currentLength, closeEvent.getFileSize());
    return Optional.of(fileDiff);
  }

  public Optional<FileDiff> onMetadataUpdate(Event.MetadataUpdateEvent metadataUpdateEvent)
      throws MetaStoreException {
    if (!inBackup(metadataUpdateEvent.getPath())) {
      return Optional.empty();
    }

    Map<String, String> parameters = new HashMap<>();
    switch (metadataUpdateEvent.getMetadataType()) {
      case TIMES:
        if (metadataUpdateEvent.getMtime() > 0) {
          parameters.put(MTIME, String.valueOf(metadataUpdateEvent.getMtime()));
        }
        break;
      case OWNER:
        Optional.ofNullable(metadataUpdateEvent.getOwnerName())
            .ifPresent(name -> parameters.put(OWNER_NAME, name));
        Optional.ofNullable(metadataUpdateEvent.getGroupName())
            .ifPresent(name -> parameters.put(GROUP_NAME, name));
        break;
      case PERMS:
        parameters.put(PERMISSION, String.valueOf(metadataUpdateEvent.getPerms().toShort()));
        break;
      case REPLICATION:
        parameters.put(BLOCK_REPLICATION, String.valueOf(metadataUpdateEvent.getReplication()));
        break;
      default:
        return Optional.empty();
    }

    if (parameters.isEmpty()) {
      return Optional.empty();
    }

    FileDiff fileDiff = fileDiffBuilder(metadataUpdateEvent.getPath())
        .diffType(FileDiffType.METADATA)
        .parameters(parameters)
        .build();
    return Optional.of(fileDiff);
  }

  public List<FileDiff> onFileRename(
      Event.RenameEvent renameEvent, FileInfo srcFileInfo) throws MetaStoreException {
    boolean srcInBackup = inBackup(renameEvent.getSrcPath());
    boolean destInBackup = inBackup(renameEvent.getDstPath());

    if (!srcInBackup && !destInBackup) {
      return Collections.emptyList();
    }

    if (srcFileInfo == null) {
      log.error(
          "Inconsistency in metastore and HDFS namespace, file not found: {}",
          renameEvent.getSrcPath());
      return Collections.emptyList();
    }

    List<FileDiff> fileDiffs;
    if (srcInBackup) {
      if (destInBackup) {
        // if both src and dest are in backup directory,
        // then generate rename diffs for all content under src
        fileDiffs = visitFileRecursively(srcFileInfo, renameEvent, this::buildRenameFileDiff);
      } else {
        // if src is in backup directory and dest isn't,
        // then simply delete all files under src on remote cluster
        fileDiffs = Collections.singletonList(getDeleteFileDiff(srcFileInfo.getPath()));
      }
    } else {
      // if dest is in backup directory and src isn't,
      // then simply copy files under dest to remote cluster
      fileDiffs = visitFileRecursively(srcFileInfo, renameEvent, this::buildCreateFileDiff);
    }

    if (fileDiffs.isEmpty()) {
      log.error(
          "Inconsistency in metastore and HDFS namespace, file not found: {}",
          renameEvent.getSrcPath());
      return Collections.emptyList();
    }
    // set first diff as base rename operation
    fileDiffs.get(0).setParameter(BASE_OPERATION, "");
    return fileDiffs;
  }

  public Optional<FileDiff> onFileDelete(String path)
      throws MetaStoreException {
    if (!inBackup(path)) {
      return Optional.empty();
    }

    FileDiff deleteFileDiff = getDeleteFileDiff(path);
    return Optional.of(deleteFileDiff);
  }

  private FileDiff toCreateDiff(FileInfo file, String path) {
    return file.isDir()
        ? toCreateDirectoryDiff(path)
        : toCreateFileDiff(file, path);
  }

  private FileDiff toCreateDirectoryDiff(String path) {
    return fileDiffBuilder(path)
        .diffType(FileDiffType.MKDIR)
        .build();
  }

  private FileDiff toAppendDiff(String path, long currentLength, long newLength) {
    Map<String, String> parameters = new HashMap<>();
    parameters.put(CopyFileAction.OFFSET_INDEX, String.valueOf(currentLength));
    parameters.put(CopyFileAction.LENGTH, String.valueOf(newLength - currentLength));

    return fileDiffBuilder(path)
        .diffType(FileDiffType.APPEND)
        .parameters(parameters)
        .build();
  }

  private FileDiff toCreateFileDiff(FileInfo file, String path) {
    Map<String, String> parameters = new HashMap<>();
    parameters.put(CopyFileAction.OFFSET_INDEX, "0");
    parameters.put(CopyFileAction.LENGTH, String.valueOf(file.getLength()));

    return fileDiffBuilder(path)
        .diffType(FileDiffType.APPEND)
        .parameters(parameters)
        .build();
  }

  private FileDiff buildRenameFileDiff(FileInfo fileInfo, Event.RenameEvent renameEvent) {
    Map<String, String> parameters = new HashMap<>();
    parameters.put(
        SyncAction.DEST,
        fileInfo.getPath().replaceFirst(
            renameEvent.getSrcPath(),
            renameEvent.getDstPath())
    );
    return fileDiffBuilder(fileInfo.getPath())
        .diffType(FileDiffType.RENAME)
        .parameters(parameters)
        .build();
  }

  private FileDiff getDeleteFileDiff(String path) {
    return fileDiffBuilder(path)
        .diffType(FileDiffType.DELETE)
        .build();
  }

  private FileDiff buildCreateFileDiff(FileInfo fileInfo, Event.RenameEvent renameEvent) {
    String newPath = fileInfo.getPath()
        .replaceFirst(renameEvent.getSrcPath(), renameEvent.getDstPath());
    return toCreateDiff(fileInfo, newPath);
  }

  private <C, T> List<T> visitFileRecursively(
      FileInfo srcFileInfo, C context,
      BiFunction<FileInfo, C, T> diffProducer)
      throws MetaStoreException {
    List<T> results = new ArrayList<>();
    results.add(diffProducer.apply(srcFileInfo, context));

    if (srcFileInfo.isDir()) {
      metaStore.getFilesByPrefixInOrder(addPathSeparator(srcFileInfo.getPath()))
          .stream()
          .map(fileInfo -> diffProducer.apply(fileInfo, context))
          .forEach(results::add);
    }

    return results;
  }

  private FileDiff.Builder fileDiffBuilder(String src) {
    return FileDiff.builder()
        .src(src)
        .state(FileDiffState.PENDING)
        .createTime(currentTimeMsSupplier.get())
        .parameters(new HashMap<>());
  }

  private boolean inBackup(String src) throws MetaStoreException {
    return metaStore.srcInBackup(src);
  }
}
