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
package org.smartdata.hdfs.scheduler;

import com.google.common.util.concurrent.RateLimiter;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.SmartContext;
import org.smartdata.action.SyncAction;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.hdfs.action.CopyDirectoryAction;
import org.smartdata.hdfs.action.CopyFileAction;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.*;
import org.smartdata.model.action.ScheduleResult;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.smartdata.model.FileDiffType.DELETE;
import static org.smartdata.utils.ConfigUtil.toRemoteClusterConfig;
import static org.smartdata.utils.FileDiffUtils.getDest;
import static org.smartdata.utils.FileDiffUtils.getLength;
import static org.smartdata.utils.FileDiffUtils.getOffset;
import static org.smartdata.utils.StringUtil.pathStartsWith;

public class CopyScheduler extends ActionSchedulerService {
  static final Logger LOG = LoggerFactory.getLogger(CopyScheduler.class);

  private static final int NON_EXISTENT_FILE_OFFSET = -1;

  // todo make this and other threshold constants configurable options
  private static final int FILE_DIFF_ARCHIVE_SIZE = 1000;
  // Merge append length threshold
  private final static long MERGE_LEN_THRESHOLD = DFSConfigKeys.DFS_BLOCK_SIZE_DEFAULT * 3;
  // Merge count length threshold
  private final static long MERGE_COUNT_THRESHOLD = 10;
  private final static int RETRY_THRESHOLD = 3;
  // Base sync batch insert size
  private final static int INITIAL_SYNC_BATCH_SIZE = 500;
  private static final List<String> SUPPORTED_ACTIONS = Collections.singletonList("sync");

  private final MetaStore metaStore;

  // Fixed rate scheduler
  private final ScheduledExecutorService executorService;
  // Global variables
  private Configuration conf;
  // <File path, file diff id>
  private final Set<String> fileLocks;
  // <actionId, file diff id>
  private final Map<Long, Long> actionDiffMap;
  // <File path, FileChain object>
  private final Map<String, ScheduleTask.FileChain> fileDiffChains;
  // <diffId, Fail times>
  private final Map<Long, Integer> fileDiffFailedTimes;
  // BaseSync queue
  private final Map<String, String> initialSyncQueue;
  private final Set<String> filesToCreate;
  // Check interval of executorService
  private final long checkInterval;
  // Cache of the file_diff
  private final Map<Long, FileDiff> fileDiffCache;
  // cache sync threshold, default 100
  private int cacheSyncTh = 100;
  // record the file_diff whether being changed
  private final Set<Long> changedFileInCacheDiffIds;
  private RateLimiter rateLimiter = null;
  // records the number of file diffs in useless states
  private final AtomicInteger numFileDiffUseless = new AtomicInteger(0);
  // record the file diff info in order for check use
  // todo encapsulate actions on archive in separate class
  private final List<FileDiff> fileDiffArchive;

  public CopyScheduler(SmartContext context, MetaStore metaStore) {
    super(context, metaStore);
    this.metaStore = metaStore;
    this.fileLocks = ConcurrentHashMap.newKeySet();
    this.actionDiffMap = new ConcurrentHashMap<>();
    this.fileDiffChains = new ConcurrentHashMap<>();
    this.fileDiffFailedTimes = new ConcurrentHashMap<>();
    this.initialSyncQueue = new ConcurrentHashMap<>();
    this.filesToCreate = ConcurrentHashMap.newKeySet();
    this.executorService = Executors.newScheduledThreadPool(2);
    this.fileDiffCache = new ConcurrentHashMap<>();
    this.changedFileInCacheDiffIds = ConcurrentHashMap.newKeySet();
    // Get conf or new default conf
    try {
      conf = getContext().getConf();
    } catch (NullPointerException e) {
      // SmartContext is empty
      conf = new Configuration();
    }
    // Conf related parameters
    cacheSyncTh = conf.getInt(SmartConfKeys
            .SMART_COPY_SCHEDULER_BASE_SYNC_BATCH,
        SmartConfKeys.SMART_COPY_SCHEDULER_BASE_SYNC_BATCH_DEFAULT);
    checkInterval = conf.getLong(SmartConfKeys.SMART_COPY_SCHEDULER_CHECK_INTERVAL,
        SmartConfKeys.SMART_COPY_SCHEDULER_CHECK_INTERVAL_DEFAULT);
    // throttle for copy action
    long throttleInMb = conf.getLong(SmartConfKeys.SMART_ACTION_COPY_THROTTLE_MB_KEY,
        SmartConfKeys.SMART_ACTION_COPY_THROTTLE_MB_DEFAULT);
    if (throttleInMb > 0) {
      rateLimiter = RateLimiter.create(throttleInMb);
    }
    try {
      this.numFileDiffUseless.addAndGet(metaStore.getUselessFileDiffNum());
    } catch (MetaStoreException e) {
      LOG.error("Failed to get num of useless file diffs!");
    }
    this.fileDiffArchive = new CopyOnWriteArrayList<>();
  }

  @Override
  public ScheduleResult onSchedule(CmdletInfo cmdletInfo, ActionInfo actionInfo,
      LaunchCmdlet cmdlet, LaunchAction action, int actionIndex) {
    if (!actionInfo.getActionName().equals("sync")) {
      return ScheduleResult.FAIL;
    }
    String srcDir = action.getArgs().get(SyncAction.SRC);
    String path = action.getArgs().get(HdfsAction.FILE_PATH);
    String destDir = action.getArgs().get(SyncAction.DEST);
    String preserveAttributes = action.getArgs().get(SyncAction.PRESERVE);
    String destPath = path.replaceFirst(srcDir, destDir);
    // Check again to avoid corner cases
    long diffId = fileDiffChains.get(path).getHead();
    if (diffId == -1) {
      // FileChain is already empty
      return ScheduleResult.FAIL;
    }
    FileDiff fileDiff = fileDiffCache.get(diffId);
    if (fileDiff == null) {
      return ScheduleResult.FAIL;
    }
    if (fileDiff.getState() != FileDiffState.PENDING) {
      // If file diff is applied or failed
      fileDiffChains.get(path).removeHead();
      fileLocks.remove(path);
      return ScheduleResult.FAIL;
    }
    // wait dependent file diff
    if (requireWait(fileDiff)) {
      return ScheduleResult.RETRY;
    }

    // Check whether src is compressed, if so, the original length of syncing file should be used.
    // Otherwise, only partial compressed file is copied. Using HDFS copy cmd or SSM copy action
    // will not have such issue, since file length is obtained from SmartDFSClient in that case,
    // where original length is acquired. For copying or syncing a compressed file, the backup
    // file will not be compressed.
    try {
      FileState fileState = metaStore.getFileState(fileDiff.getSrc());
      if (fileState instanceof CompressionFileState && getLength(fileDiff) != null) {
        long length = ((CompressionFileState) fileState).getOriginalLength();
        fileDiff.getParameters().put("-length", Long.toString(length));
      }
    } catch (MetaStoreException e) {
      LOG.error("Failed to get FileState, the syncing file's length may be " +
          "incorrect if it is compressed", e);
    }

    switch (fileDiff.getDiffType()) {
      case APPEND:
        action.setActionType("copy");
        action.getArgs().put(CopyFileAction.DEST_PATH, destPath);
        if (preserveAttributes != null) {
          action.getArgs().put(CopyFileAction.PRESERVE, preserveAttributes);
        }
        if (rateLimiter != null) {
          String strLen = getLength(fileDiff);
          if (strLen != null) {
            int appendLen = (int)(Long.parseLong(strLen) >> 20);
            if (appendLen > 0) {
              if (!rateLimiter.tryAcquire(appendLen)) {
                if (LOG.isDebugEnabled()) {
                  LOG.debug("Cancel Scheduling COPY action {} due to throttling.", actionInfo);
                }
                return ScheduleResult.RETRY;
              }
            }
          }
        }
        break;
      case MKDIR:
        action.setActionType("dircopy");
        action.getArgs().put(CopyDirectoryAction.DEST_PATH, destPath);
        if (preserveAttributes != null) {
          action.getArgs().put(CopyDirectoryAction.PRESERVE, preserveAttributes);
        }
        break;
      case DELETE:
        action.setActionType("delete");
        action.getArgs().put(HdfsAction.FILE_PATH, destPath);
        break;
      case RENAME:
        action.setActionType("rename");
        action.getArgs().put(HdfsAction.FILE_PATH, destPath);
        // TODO scope check
        String remoteDest = getDest(fileDiff);
        action.getArgs().put("-dest", remoteDest.replaceFirst(srcDir, destDir));
        fileDiff.getParameters().remove("-dest");
        break;
      case METADATA:
        action.setActionType("metadata");
        action.getArgs().put(HdfsAction.FILE_PATH, destPath);
        break;
      default:
        break;
    }
    // Put all parameters into args
    action.getArgs().putAll(fileDiff.getParameters());
    actionDiffMap.put(actionInfo.getActionId(), diffId);
    if (!fileDiffFailedTimes.containsKey(diffId)) {
      fileDiffFailedTimes.put(diffId, 1);
    }
    return ScheduleResult.SUCCESS;
  }

  @Override
  public List<String> getSupportedActions() {
    return SUPPORTED_ACTIONS;
  }
  
  private boolean isFileLocked(String path) {
    if(fileLocks.isEmpty()) {
      LOG.debug("File Lock is empty. Current path = {}", path);
    }

    // File is locked
    return fileLocks.contains(path)
        // File is in base sync queue
        || initialSyncQueue.containsKey(path)
        // File Chain is not ready
        || !fileDiffChains.containsKey(path)
        // File Chain is empty
        || fileDiffChains.get(path).isEmpty();
  }

  private boolean requireWait(FileDiff fileDiff) {
    for (FileDiff archiveDiff : fileDiffArchive) {
      if (fileDiff.getDiffId() == archiveDiff.getDiffId()) {
        break;
      }
      if (!FileDiffState.isTerminalState(archiveDiff.getState())) {
        if (pathStartsWith(fileDiff.getSrc(), archiveDiff.getSrc())
            || pathStartsWith(archiveDiff.getSrc(), fileDiff.getSrc())) {
          return true;
        }
      }
    }
    return false;
  }

  @Override
  public boolean onSubmit(CmdletInfo cmdletInfo, ActionInfo actionInfo, int actionIndex)
      throws IOException {
    // check args
    if (actionInfo.getArgs() == null) {
      throw new IOException("No arguments for the action");
    }
    String path = actionInfo.getArgs().get(HdfsAction.FILE_PATH);
    LOG.debug("Submit file {} with lock {}", path, fileLocks);
    // If locked then false
    if (!isFileLocked(path)) {
      // Lock this file/chain to avoid conflict
      fileLocks.add(path);
      return true;
    }
    throw new IOException("The submit file " + path + " is in use by another program or user");
  }

  @Override
  public void onActionFinished(CmdletInfo cmdletInfo, ActionInfo actionInfo, int actionIndex) {
    // Remove lock
    FileDiff fileDiff = null;
    if (actionInfo.isFinished()) {
      try {
        long did = actionDiffMap.get(actionInfo.getActionId());
        // Remove for action diff map
        actionDiffMap.remove(actionInfo.getActionId());

        if (fileDiffCache.containsKey(did)) {
          fileDiff = fileDiffCache.get(did);
        } else {
          LOG.error("Duplicate sync action->[ {} ] is triggered", did);
          return;
        }
        if (fileDiff == null) {
          return;
        }
        if (actionInfo.isSuccessful()) {
          fileDiffTerminated(fileDiff);
          //update state in cache
          updateFileDiffInCache(did, FileDiffState.APPLIED);
        } else {
          if (fileDiffFailedTimes.containsKey(did)) {
            int curr = fileDiffFailedTimes.get(did);
            if (curr >= RETRY_THRESHOLD) {
              fileDiffTerminated(fileDiff);
              //update state in cache
              updateFileDiffInCache(did, FileDiffState.FAILED);
            } else {
              fileDiffFailedTimes.put(did, curr + 1);
              // Unlock this file for retry
              fileLocks.remove(fileDiff.getSrc());
            }
          } else {
            fileDiffTerminated(fileDiff);
            updateFileDiffInCache(did, FileDiffState.FAILED);
          }
        }
      } catch (MetaStoreException e) {
        LOG.error("Mark sync action in metastore failed!", e);
      } catch (Exception e) {
        LOG.error("Sync action error", e);
      }
    }
  }

  private void fileDiffTerminated(FileDiff fileDiff) {
    if (fileDiffChains.containsKey(fileDiff.getSrc())) {
      // Remove chain top
      fileDiffChains.get(fileDiff.getSrc()).removeHead();
    }
    // remove from fileDiffMap which is for retry use
    fileDiffFailedTimes.remove(fileDiff.getDiffId());
  }

  private void fileDiffTerminatedInternal(FileDiff fileDiff) {
    if (fileDiffChains.containsKey(fileDiff.getSrc())) {
      // Remove the fileDiff from chain
      fileDiffChains.get(fileDiff.getSrc()).removeFromChain(fileDiff);
    }
    // remove from fileDiffMap which is for retry use
    fileDiffFailedTimes.remove(fileDiff.getDiffId());
  }

  private void runBatchInitialSync() throws MetaStoreException {
    if (initialSyncQueue.isEmpty()) {
      return;
    }
    LOG.debug("Base Sync size = {}", initialSyncQueue.size());

    List<FileDiff> batchFileDiffs = new ArrayList<>();
    List<String> handledFilePaths = new ArrayList<>();
    int index = 0;

    for (Map.Entry<String, String> syncQueueEntry : initialSyncQueue.entrySet()) {
      if (index++ >= INITIAL_SYNC_BATCH_SIZE) {
        break;
      }
      FileDiff fileDiff = runFileInitialSync(syncQueueEntry.getKey(), syncQueueEntry.getValue());
      if (fileDiff != null) {
        batchFileDiffs.add(fileDiff);
      }
      handledFilePaths.add(syncQueueEntry.getKey());
    }

    // Batch Insert
    List<Long> diffIds = metaStore.insertFileDiffs(batchFileDiffs);
    for (int i = 0; i < diffIds.size(); i++) {
      batchFileDiffs.get(i).setDiffId(diffIds.get(i));
    }
    fileDiffArchive.addAll(batchFileDiffs);

    // Remove from initialSyncQueue
    for (String src : handledFilePaths) {
      initialSyncQueue.remove(src);
    }
  }

  private List<FileStatus> listFileStatusesOfDirs(String dirName) {
    List<FileStatus> fileStatuses = new ArrayList<>();
    try {
      // We simply use local HDFS conf for getting remote file system.
      // The smart file system configured for local HDFS should not be
      // introduced to remote file system.
      Configuration remoteConf = toRemoteClusterConfig(conf);
      FileSystem fs = FileSystem.get(URI.create(dirName), remoteConf);

      FileStatus[] directoryFileStatuses = fs.listStatus(new Path(dirName));
      for (FileStatus fileStatus : directoryFileStatuses) {
        // add directory
        fileStatuses.add(fileStatus);

        if (!fileStatus.isDirectory()) {
          continue;
        }

        //all the file in this fileStatuses
        // todo replace recursion with queue
        List<FileStatus> childFileStatuses = listFileStatusesOfDirs(fileStatus.getPath().getName());
        if (!childFileStatuses.isEmpty()) {
          fileStatuses.addAll(childFileStatuses);
        }
      }
    } catch (IOException e) {
      LOG.debug("Fetch remote file list error!", e);
    }
    return fileStatuses;
  }

  private void initialSync(String srcDir, String destDir) throws MetaStoreException {
    List<FileInfo> srcFiles = metaStore.getFilesByPrefix(srcDir);
    LOG.info("Directory initial sync {} files", srcFiles.size());

    // <file name, fileInfo>
    Map<String, FileInfo> filesToSync = new HashMap<>();
    for (FileInfo fileInfo : srcFiles) {
      // Remove prefix/parent
      filesToSync.put(fileInfo.getPath().replaceFirst(srcDir, ""), fileInfo);
    }

    // recursively file lists
    List<FileStatus> fileStatuses = listFileStatusesOfDirs(destDir);
    if (fileStatuses.isEmpty()) {
      LOG.debug("Remote directory is empty!");
    } else {
      LOG.debug("Remote directory contains {} files!", fileStatuses.size());
      for (FileStatus fileStatus : fileStatuses) {
        // only get file name
        // todo it can be buggy because of .getPath().getName()
        String destName = fileStatus.getPath().getName();
        if (filesToSync.containsKey(destName)) {
          FileInfo fileInfo = filesToSync.get(destName);
          String src = fileInfo.getPath();
          String dest = src.replaceFirst(srcDir, destDir);
          initialSyncQueue.put(src, dest);
          filesToSync.remove(destName);
        }
      }
    }

    LOG.debug("Directory Base Sync {} files", filesToSync.size());
    for (FileInfo fileInfo : filesToSync.values()) {
      String src = fileInfo.getPath();
      String dest = src.replaceFirst(srcDir, destDir);
      initialSyncQueue.put(src, dest);
      if (!fileInfo.isdir()) {
       filesToCreate.add(src);
      }
    }
    runBatchInitialSync();
  }

  private void mergePendingDiffs(String src) throws MetaStoreException {
    // Lock file to avoid diff apply
    fileLocks.add(src);
    try {
      // Mark all related diff in cache as Merged
      if (fileDiffChains.containsKey(src)) {
        fileDiffChains.get(src).mergeAllDiffs();
        fileDiffChains.remove(src);
        pushCacheToDB();
      }
      // Mark all related diff in metastore as Merged
      List<Long> pendingDiffIds = metaStore.getFileDiffsByFileName(src)
          .stream()
          .filter(fileDiff -> fileDiff.getState() == FileDiffState.PENDING)
          .map(FileDiff::getDiffId)
          .collect(Collectors.toList());

      metaStore.batchUpdateFileDiff(pendingDiffIds, FileDiffState.MERGED);
      pendingDiffIds.forEach(id -> updateFileDiffArchive(id, FileDiffState.MERGED));
    } finally {
      // Unlock this file
      fileLocks.remove(src);
    }
  }

  private FileDiff runFileInitialSync(String src, String dest) throws MetaStoreException {
    FileInfo srcFileInfo = metaStore.getFile(src);
    if (srcFileInfo == null || fileLocks.contains(src)) {
      // Primary file doesn't exist or file is syncing
      return null;
    }

    mergePendingDiffs(src);

    if (srcFileInfo.isdir()) {
      FileDiff fileDiff = new FileDiff(FileDiffType.MKDIR, FileDiffState.PENDING);
      fileDiff.setSrc(src);
      return fileDiff;
    }

    long remoteFileOffset = filesToCreate.remove(src)
        ? NON_EXISTENT_FILE_OFFSET
        : remoteFileLen(dest);

    // todo use checksums instead of offsets
    if (remoteFileOffset == srcFileInfo.getLength()) {
      LOG.info("Src and dest files are equal, no need to copy");
      return null;
    }

    if (remoteFileOffset == NON_EXISTENT_FILE_OFFSET) {
      remoteFileOffset = 0;
    } else if (remoteFileOffset > srcFileInfo.getLength()) {
      // Remove dirty remote file
      // todo why source?
      storeFileDelete(src);
      remoteFileOffset = 0;
    }

    // Copy tails to remote
    FileDiff fileDiff = new FileDiff(FileDiffType.APPEND, FileDiffState.PENDING);
    fileDiff.setSrc(src);
    // Append changes to remote files
    fileDiff.getParameters()
        .put("-length", String.valueOf(srcFileInfo.getLength() - remoteFileOffset));
    fileDiff.getParameters().put("-offset", String.valueOf(remoteFileOffset));
    fileDiff.setRuleId(-1);
    return fileDiff;
  }

  private void storeFileDelete(String path) throws MetaStoreException {
    FileDiff fileDiff = new FileDiff(DELETE, FileDiffState.PENDING);
    fileDiff.setSrc(path);
    metaStore.insertFileDiff(fileDiff);
  }

  private long remoteFileLen(String path) {
    try {
      FileSystem fs = FileSystem.get(URI.create(path), conf);
      FileStatus fileStatus = fs.getFileStatus(new Path(path));
      return fileStatus.getLen();
    } catch (IOException e) {
      return NON_EXISTENT_FILE_OFFSET;
    }
  }

  /***
   * add fileDiff to Cache, if diff is already in cache, then print error log
   */
  private void addDiffToCache(FileDiff fileDiff) {
    LOG.debug("Add FileDiff Cache into file_diff cache");
    if (fileDiffCache.containsKey(fileDiff.getDiffId())) {
      LOG.error("FileDiff {} already in cache!", fileDiff);
      return;
    }
    fileDiffCache.put(fileDiff.getDiffId(), fileDiff);
  }

  private synchronized void updateFileDiffInCache(Long diffId,
      FileDiffState fileDiffState) throws MetaStoreException {
    LOG.debug("Update FileDiff");
    if (!fileDiffCache.containsKey(diffId)) {
      return;
    }
    FileDiff fileDiff = fileDiffCache.get(diffId);
    fileDiff.setState(fileDiffState);
    // Update
    changedFileInCacheDiffIds.add(diffId);
    updateFileDiffArchive(diffId, fileDiffState);
    if (changedFileInCacheDiffIds.size() >= cacheSyncTh) {
      // update
      pushCacheToDB();
    }
    if (FileDiffState.isUselessFileDiff(fileDiffState)) {
      numFileDiffUseless.incrementAndGet();
    }
  }

  private synchronized void updateFileDiffArchive(long diffId, FileDiffState state) {
    for (FileDiff diff : fileDiffArchive) {
      if (diff.getDiffId() == diffId) {
        diff.setState(state);
      }
    }
  }

  /***
   * delete cache and remove file lock if necessary
   */
  private void deleteDiffInCache(Long diffId) {
    LOG.debug("Delete FileDiff in cache");
    if (fileDiffCache.containsKey(diffId)) {
      FileDiff fileDiff = fileDiffCache.get(diffId);
      fileDiffCache.remove(diffId);
      changedFileInCacheDiffIds.remove(diffId);
      // Remove file lock
      fileLocks.remove(fileDiff.getSrc());
    }
  }

  private synchronized void pushCacheToDB() throws MetaStoreException {
    List<FileDiff> updatedFileDiffs = new ArrayList<>();

    // Only check changed cache rather than full cache
    List<Long> terminalFileDiffsToDelete = changedFileInCacheDiffIds.stream()
        .map(fileDiffCache::get)
        .filter(Objects::nonNull)
        .peek(updatedFileDiffs::add)
        .filter(diff -> FileDiffState.isTerminalState(diff.getState()))
        .map(FileDiff::getDiffId)
        .collect(Collectors.toList());

    // Push cache to metastore
    if (!updatedFileDiffs.isEmpty()) {
      LOG.debug("Push FileDiff from cache to metastore");
      metaStore.updateFileDiff(updatedFileDiffs);
    }
    // Remove file diffs in cache and file lock
    terminalFileDiffsToDelete.forEach(this::deleteDiffInCache);
  }

  @Override
  public void init() throws IOException {
  }

  @Override
  public void start() throws IOException {
    executorService.scheduleAtFixedRate(
        new CopyScheduler.ScheduleTask(), 0, checkInterval,
        TimeUnit.MILLISECONDS);
    // The PurgeFileDiffTask runs in the period of 1800s
    executorService.scheduleAtFixedRate(
        new PurgeFileDiffTask(conf), 0, 1800, TimeUnit.SECONDS);
  }

  @Override
  public void stop() throws IOException {
    try {
      runBatchInitialSync();
    } catch (MetaStoreException e) {
      throw new IOException(e);
    } finally {
      executorService.shutdown();
    }
  }

  private class ScheduleTask implements Runnable {

    private void syncFileDiff() {
      try {
        pushCacheToDB();
        List<FileDiff> pendingDiffs = metaStore.getPendingDiff();
        processPendingDiffs(pendingDiffs);
      } catch (MetaStoreException e) {
        LOG.error("Sync fileDiffs error", e);
      }
    }

    private void processPendingDiffs(
        List<FileDiff> fileDiffs) throws MetaStoreException {
      for (FileDiff fileDiff: fileDiffs) {
        addToFileDiffArchive(fileDiff);
      }

      LOG.debug("Size of Pending diffs {}", fileDiffs.size());
      if (fileDiffs.isEmpty() && initialSyncQueue.isEmpty()) {
        LOG.debug("All Backup directories are synced");
        return;
      }

      // Merge all existing fileDiffs into fileChains
      for (FileDiff fileDiff : fileDiffs) {
        if (fileDiff.getDiffType() == FileDiffType.BASESYNC) {
          metaStore.updateFileDiff(fileDiff.getDiffId(), FileDiffState.MERGED);
          updateFileDiffArchive(fileDiff.getDiffId(), FileDiffState.MERGED);
          initialSync(fileDiff.getSrc(), getDest(fileDiff));
          return;
        }

        if (fileDiffCache.containsKey(fileDiff.getDiffId())) {
          // Skip diff in cache
          continue;
        }
        if (initialSyncQueue.containsKey(fileDiff.getSrc())) {
          // Will be directly sync
          continue;
        }

        // Get or create fileChain
        FileChain fileChain = fileDiffChains.computeIfAbsent(
            fileDiff.getSrc(), FileChain::new);
        fileChain.addToChain(fileDiff);
      }
    }

    private void addToFileDiffArchive(FileDiff newFileDiff) {
      for (FileDiff fileDiff: fileDiffArchive) {
        if (fileDiff.getDiffId() == newFileDiff.getDiffId()) {
          return;
        }
      }
      fileDiffArchive.add(newFileDiff);
      int index = 0;
      while (fileDiffArchive.size() > FILE_DIFF_ARCHIVE_SIZE && index < FILE_DIFF_ARCHIVE_SIZE) {
        if (FileDiffState.isTerminalState(fileDiffArchive.get(index).getState())) {
          fileDiffArchive.remove(index);
          continue;
        }
        index++;
      }
    }

    @Override
    public void run() {
      try {
        runBatchInitialSync();
        syncFileDiff();
        // addToRunning();
      } catch (Exception e) {
        LOG.error("CopyScheduler Run Error", e);
      }
    }

    private class FileChain {
      // Current append length in chain
      private long currAppendLength;
      // Current file path/name
      private final String filePath;
      // file diff id
      private final List<Long> diffChain;
      // append file diff id
      private final List<Long> appendChain;

      FileChain(String filePath) {
        this.diffChain = new ArrayList<>();
        this.appendChain = new ArrayList<>();
        this.currAppendLength = 0;
        this.filePath = filePath;
      }

      boolean isEmpty() {
        return diffChain.isEmpty();
      }

      void addToChain(FileDiff fileDiff) throws MetaStoreException {
        addDiffToCache(fileDiff);

        long diffId = fileDiff.getDiffId();

        switch (fileDiff.getDiffType()) {
          case APPEND:
            String offset = getOffset(fileDiff);
            // check if it's actually a create event and we have previous
            // events connected with this path
            if (offset != null && offset.equals("0") && !diffChain.isEmpty()) {
              // mark previous events connected with this path as merged
              mergeAllDiffs();
            }

            if (currAppendLength >= MERGE_LEN_THRESHOLD ||
                appendChain.size() >= MERGE_COUNT_THRESHOLD) {
              mergeAppend();
            }

            // Add Append to Append Chain
            appendChain.add(diffId);
            // Increase Append length
            currAppendLength += Long.parseLong(getLength(fileDiff));
            diffChain.add(diffId);
            break;
          case RENAME:
            if (isRenameSyncedFile(fileDiff)) {
              // Add New Name to Name Chain
              mergeRename(fileDiff);
              break;
            }
            fileDiffTerminatedInternal(fileDiff);
            // discard rename file diff due to not synced
            updateFileDiffInCache(fileDiff.getDiffId(), FileDiffState.FAILED);
            discardDirtyData(fileDiff);
            break;
          case DELETE:
            mergeDelete(fileDiff);
            break;
          default:
            // Metadata or mkdir
            diffChain.add(diffId);
        }
      }

      void discardDirtyData(FileDiff fileDiff) throws MetaStoreException {
        // Clean dirty data
        List<BackUpInfo> backUpInfos = metaStore.getBackUpInfoBySrc(fileDiff.getSrc());
        for (BackUpInfo backUpInfo : backUpInfos) {
          FileDiff deleteFileDiff = new FileDiff(DELETE, FileDiffState.PENDING);
          // use the rename file diff's src as delete file diff src
          deleteFileDiff.setSrc(fileDiff.getSrc());
          String destPath = deleteFileDiff.getSrc().replaceFirst(backUpInfo.getSrc(), backUpInfo.getDest());
          //put sync's dest path in parameter for delete use
          deleteFileDiff.getParameters().put("-dest", destPath);
          long did = metaStore.insertFileDiff(deleteFileDiff);
          deleteFileDiff.setDiffId(did);
          fileDiffArchive.add(deleteFileDiff);
        }
      }

      void mergeAppend() throws MetaStoreException {
        if (fileLocks.contains(filePath)) {
          return;
        }
        LOG.debug("Append Merge Triggered!");
        // Lock file to avoid File Chain being processed
        fileLocks.add(filePath);
        try {
          long offset = Integer.MAX_VALUE;
          long totalLength = 0;
          long lastAppend = -1;
          for (long diffId : appendChain) {
            FileDiff fileDiff = fileDiffCache.get(diffId);

            if (fileDiff == null || fileDiff.getState() == FileDiffState.APPLIED) {
              continue;
            }

            long currOffset = Long.parseLong(getOffset(fileDiff));

            offset = Math.min(offset, currOffset);

            if (currOffset != offset && currOffset != totalLength + offset) {
              // Check offset and length to avoid dirty append
              break;
            }
            updateFileDiffInCache(diffId, FileDiffState.APPLIED);
            // Add current file length to length
            totalLength += Long.parseLong(getLength(fileDiff));
            lastAppend = diffId;
          }
          if (lastAppend == -1) {
            return;
          }
          FileDiff fileDiff = fileDiffCache.get(lastAppend);
          fileDiff.getParameters().put("-offset", "" + offset);
          fileDiff.getParameters().put("-length", "" + totalLength);
          // Update fileDiff in metastore
          changedFileInCacheDiffIds.add(fileDiff.getDiffId());
        } finally {
          // Unlock file
          fileLocks.remove(filePath);
        }
        currAppendLength = 0;
        appendChain.clear();
      }

      void mergeDelete(FileDiff fileDiff) throws MetaStoreException {
        LOG.debug("Delete Merge Triggered!");
        for (FileDiff archiveDiff : fileDiffArchive) {
          if (archiveDiff.getDiffId() == fileDiff.getDiffId()) {
            break;
          }
          if (FileDiffState.isTerminalState(archiveDiff.getState())) {
            continue;
          }

          if (pathStartsWith(archiveDiff.getSrc(), fileDiff.getSrc())) {
            fileDiffTerminatedInternal(archiveDiff);
            updateFileDiffInCache(archiveDiff.getDiffId(), FileDiffState.APPLIED);
          }
        }
        diffChain.add(fileDiff.getDiffId());
      }

      void mergeRename(FileDiff fileDiff) throws MetaStoreException {
        // Rename action will affect all append actions
        if (fileLocks.contains(filePath)) {
          return;
        }
        LOG.debug("Rename Merge Triggered!");
        // Lock file to avoid File Chain being processed
        fileLocks.add(filePath);
        try {
          String newName = getDest(fileDiff);
          boolean isCreate = false;
          for (long diffId : appendChain) {
            FileDiff appendFileDiff = fileDiffCache.get(diffId);
            if (appendFileDiff != null &&
                appendFileDiff.getState() != FileDiffState.APPLIED) {
              // update append diff path with renamed one
              appendFileDiff.setSrc(newName);
              changedFileInCacheDiffIds.add(appendFileDiff.getDiffId());
            }
            if (Objects.equals(getOffset(fileDiff), "0")) {
              isCreate = true;
            }
          }
          if (isCreate) {
            // mark rename event as applied, because we've already
            // changed create (append) event path
            updateFileDiffInCache(fileDiff.getDiffId(), FileDiffState.APPLIED);
          } else {
            // Insert rename fileDiff to head
            diffChain.add(0, fileDiff.getDiffId());
          }
        } finally {
          // Unlock file
          fileLocks.remove(filePath);
        }
      }

      boolean isRenameSyncedFile(FileDiff renameFileDiff) throws MetaStoreException {
        String path = renameFileDiff.getSrc();
        // get unfinished append file diff
        List<FileDiff> unfinishedAppendFileDiff = new ArrayList<>();
        FileDiff renameDiffInArchive = null;
        for (FileDiff fileDiff : fileDiffArchive) {
          if (fileDiff.getDiffId() == renameFileDiff.getDiffId()) {
            renameDiffInArchive = fileDiff;
            break;
          }

          if (fileDiff.getDiffType() != FileDiffType.APPEND ||
              !pathStartsWith(path, fileDiff.getSrc())) {
            continue;
          }
          if (fileDiff.getState() == FileDiffState.PENDING) {
            unfinishedAppendFileDiff.add(fileDiff);
          }
        }

        if (unfinishedAppendFileDiff.isEmpty()) {
          return true;
        }

        for (FileDiff unfinished : unfinishedAppendFileDiff) {
          FileDiff fileDiff = fileDiffCache.get(unfinished.getDiffId());
          if (fileDiff == null) {
            fileDiff = unfinished;
          }
          fileDiffTerminatedInternal(fileDiff);
          updateFileDiffInCache(fileDiff.getDiffId(), FileDiffState.FAILED);
          // add a new append file diff with new name
          FileDiff newFileDiff = new FileDiff(FileDiffType.APPEND, FileDiffState.PENDING);
          newFileDiff.getParameters().putAll(fileDiff.getParameters());
          newFileDiff.setSrc(fileDiff.getSrc().replaceFirst(
              renameFileDiff.getSrc(), getDest(fileDiff)));
          long did = metaStore.insertFileDiff(newFileDiff);
          newFileDiff.setDiffId(did);
          fileDiffArchive.add(fileDiffArchive.indexOf(renameDiffInArchive), newFileDiff);
        }
        return false;
      }

      long getHead() {
        if (diffChain.isEmpty()) {
          return -1;
        }
        return diffChain.get(0);
      }

      long removeHead() {
        if (diffChain.isEmpty()) {
          return -1;
        }
        long fid = diffChain.get(0);
        if (!appendChain.isEmpty() && fid == appendChain.get(0)) {
          appendChain.remove(0);
        }
        diffChain.remove(0);
        if (diffChain.isEmpty()) {
          fileDiffChains.remove(filePath);
        }
        return fid;
      }

      void removeFromChain(FileDiff fileDiff) {
        diffChain.removeIf(aLong -> aLong == fileDiff.getDiffId());
        if (diffChain.isEmpty()) {
          fileDiffChains.remove(filePath);
        }
      }

      void mergeAllDiffs() throws MetaStoreException {
        List<Long> diffIds = new ArrayList<>();
        for (long diffId : diffChain) {
          if (fileDiffCache.containsKey(diffId)) {
            updateFileDiffInCache(diffId, FileDiffState.MERGED);
          } else {
            diffIds.add(diffId);
            LOG.error("FileDiff {} is in chain but not in cache", diffId);
          }
        }
        if (!diffIds.isEmpty()) {
          metaStore.batchUpdateFileDiff(diffIds, FileDiffState.MERGED);
        }
        diffChain.clear();
        currAppendLength = 0;
        appendChain.clear();
      }
    }
  }

  private class PurgeFileDiffTask implements Runnable {
    public int maxNumRecords;

    public PurgeFileDiffTask(Configuration conf){
      this.maxNumRecords = conf.getInt(SmartConfKeys.SMART_FILE_DIFF_MAX_NUM_RECORDS_KEY,
          SmartConfKeys.SMART_FILE_DIFF_MAX_NUM_RECORDS_DEFAULT);
    }

    @Override
    public void run() {
      if (numFileDiffUseless.get() <= maxNumRecords) {
        return;
      }
      try {
        numFileDiffUseless.addAndGet(-metaStore.deleteUselessFileDiff(maxNumRecords));
      } catch (MetaStoreException e) {
        LOG.error("Error occurs when delete useless file diff!");
      }
    }
  }
}
