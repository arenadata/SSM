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
package org.smartdata.metastore;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.exception.NotFoundException;
import org.smartdata.metaservice.BackupMetaService;
import org.smartdata.metaservice.CmdletMetaService;
import org.smartdata.metaservice.CopyMetaService;
import org.smartdata.metastore.dao.ActionDao;
import org.smartdata.metastore.dao.BackUpInfoDao;
import org.smartdata.metastore.dao.CacheFileDao;
import org.smartdata.metastore.dao.ClusterConfigDao;
import org.smartdata.metastore.dao.ClusterInfoDao;
import org.smartdata.metastore.dao.CmdletDao;
import org.smartdata.metastore.dao.CompressionFileDao;
import org.smartdata.metastore.dao.DaoProvider;
import org.smartdata.metastore.dao.ErasureCodingPolicyDao;
import org.smartdata.metastore.dao.FileAccessDao;
import org.smartdata.metastore.dao.FileAccessPartitionDao;
import org.smartdata.metastore.dao.FileDiffDao;
import org.smartdata.metastore.dao.FileInfoDao;
import org.smartdata.metastore.dao.FileStateDao;
import org.smartdata.metastore.dao.GeneralDao;
import org.smartdata.metastore.dao.GlobalConfigDao;
import org.smartdata.metastore.dao.MetaStoreHelper;
import org.smartdata.metastore.dao.RuleDao;
import org.smartdata.metastore.dao.SmallFileDao;
import org.smartdata.metastore.dao.StorageDao;
import org.smartdata.metastore.dao.SystemInfoDao;
import org.smartdata.metastore.dao.UserActivityDao;
import org.smartdata.metastore.dao.WhitelistDao;
import org.smartdata.metastore.db.DbSchemaManager;
import org.smartdata.metastore.db.metadata.DbMetadataProvider;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.metastore.utils.MetaStoreUtils;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.BackUpInfo;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.ClusterConfig;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.CompactFileState;
import org.smartdata.model.CompressionFileState;
import org.smartdata.model.ErasureCodingPolicyInfo;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffState;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoDiff;
import org.smartdata.model.FileState;
import org.smartdata.model.GlobalConfig;
import org.smartdata.model.NormalFileState;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.S3FileState;
import org.smartdata.model.StorageCapacity;
import org.smartdata.model.SystemInfo;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Operations supported for upper functions.
 */
public class MetaStore implements CopyMetaService,
    CmdletMetaService, BackupMetaService, AutoCloseable {
  static final Logger LOG = LoggerFactory.getLogger(MetaStore.class);

  private final DbSchemaManager dbSchemaManager;

  private final DbMetadataProvider dbMetadataProvider;
  private final TransactionRunner defaultTransactionRunner;

  private Map<Integer, String> mapStoragePolicyIdName = null;
  private Map<String, Integer> mapStoragePolicyNameId = null;
  private Map<String, StorageCapacity> mapStorageCapacity = null;
  private Map<String, Pattern> backupSourcePatterns = null;
  private final RuleDao ruleDao;
  private final CmdletDao cmdletDao;
  private final ActionDao actionDao;
  private final FileInfoDao fileInfoDao;
  private final CacheFileDao cacheFileDao;
  private final StorageDao storageDao;
  private final FileDiffDao fileDiffDao;
  private final FileAccessDao fileAccessDao;
  private final FileAccessPartitionDao fileAccessPartitionDao;
  private final MetaStoreHelper metaStoreHelper;
  private final ClusterConfigDao clusterConfigDao;
  private final GlobalConfigDao globalConfigDao;
  private final BackUpInfoDao backUpInfoDao;
  private final ClusterInfoDao clusterInfoDao;
  private final SystemInfoDao systemInfoDao;
  private final FileStateDao fileStateDao;
  private final CompressionFileDao compressionFileDao;
  private final GeneralDao generalDao;
  private final SmallFileDao smallFileDao;
  private final ErasureCodingPolicyDao ecDao;
  private final WhitelistDao whitelistDao;
  private final UserActivityDao userActivityDao;
  private final DBPool dbPool;

  public MetaStore(DBPool pool,
                   DbSchemaManager dbSchemaManager,
                   DaoProvider daoProvider,
                   DbMetadataProvider dbMetadataProvider,
                   PlatformTransactionManager transactionManager) throws MetaStoreException {
    this.dbPool = pool;
    this.dbSchemaManager = dbSchemaManager;
    this.dbMetadataProvider = dbMetadataProvider;
    this.defaultTransactionRunner = new TransactionRunner(transactionManager);
    ruleDao = daoProvider.ruleDao();
    cmdletDao = daoProvider.cmdletDao();
    actionDao = daoProvider.actionDao();
    fileInfoDao = daoProvider.fileInfoDao();
    cacheFileDao = daoProvider.cacheFileDao();
    storageDao = daoProvider.storageDao();
    fileDiffDao = daoProvider.fileDiffDao();
    metaStoreHelper = new MetaStoreHelper(pool.getDataSource());
    clusterConfigDao = daoProvider.clusterConfigDao();
    globalConfigDao = daoProvider.globalConfigDao();
    backUpInfoDao = daoProvider.backUpInfoDao();
    clusterInfoDao = daoProvider.clusterInfoDao();
    systemInfoDao = daoProvider.systemInfoDao();
    fileStateDao = daoProvider.fileStateDao();
    compressionFileDao = daoProvider.compressionFileDao();
    generalDao = daoProvider.generalDao();
    smallFileDao = daoProvider.smallFileDao();
    ecDao = daoProvider.ecDao();
    whitelistDao = daoProvider.whitelistDao();
    userActivityDao = daoProvider.userActivityDao();
    fileAccessPartitionDao = daoProvider.fileAccessPartitionDao();
    fileAccessDao = daoProvider.fileAccessDao();
  }

  public DbMetadataProvider dbMetadataProvider() {
    return dbMetadataProvider;
  }

  public UserActivityDao userActivityDao() {
    return userActivityDao;
  }

  public CmdletDao cmdletDao() {
    return cmdletDao;
  }

  public ActionDao actionDao() {
    return actionDao;
  }

  public RuleDao ruleDao() {
    return ruleDao;
  }

  public FileAccessDao accessCountEventDao() {
    return fileAccessDao;
  }

  public CacheFileDao cacheFileDao() {
    return cacheFileDao;
  }

  public FileInfoDao fileInfoDao() {
    return fileInfoDao;
  }

  public FileAccessPartitionDao fileAccessPartitionDao() {
    return fileAccessPartitionDao;
  }


  public PlatformTransactionManager transactionManager() {
    return defaultTransactionRunner.getTransactionManager();
  }

  public DataSource getDataSource() {
    return dbPool.getDataSource();
  }

  public Long queryForLong(String sql) throws MetaStoreException {
    try {
      return generalDao.queryForLong(sql);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }


  /**
   * Store a single file info into database.
   */
  public void insertFile(FileInfo file)
      throws MetaStoreException {
    updateCache();
    fileInfoDao.insert(file);
  }


  /**
   * Store files info into database.
   */
  public void insertFiles(FileInfo[] files)
      throws MetaStoreException {
    updateCache();
    fileInfoDao.insert(files);
  }

  public void updateFileByPath(String path, FileInfoDiff fileUpdate) {
    fileInfoDao.updateByPath(path, fileUpdate);
  }

  public void unlinkRootDirectory() {
    fileInfoDao.deleteAll();
    fileStateDao.deleteAll();
    smallFileDao.deleteAll();
  }

  public void unlinkFile(String path, boolean isDirectory) {
    fileInfoDao.deleteByPath(path, isDirectory);
    fileStateDao.deleteByPath(path, isDirectory);
    smallFileDao.deleteByPath(path, isDirectory);
  }

  public void renameFile(String oldPath, String newPath, boolean isDirectory) {
    fileInfoDao.renameFile(oldPath, newPath, isDirectory);
    fileStateDao.renameFile(oldPath, newPath, isDirectory);
    smallFileDao.renameFile(oldPath, newPath, isDirectory);
  }

  public void updateFileStoragePolicy(String path, String policyName)
      throws MetaStoreException {
    if (mapStoragePolicyIdName == null) {
      updateCache();
    }
    if (!mapStoragePolicyNameId.containsKey(policyName)) {
      throw new MetaStoreException("Unknown storage policy name '"
          + policyName + "'");
    }
    try {
      storageDao.updateFileStoragePolicy(path, mapStoragePolicyNameId.get(policyName));
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public FileInfo getFile(long fid) throws MetaStoreException {
    updateCache();
    try {
      return fileInfoDao.getById(fid);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public FileInfo getFile(String path) throws MetaStoreException {
    updateCache();
    try {
      return fileInfoDao.getByPath(path);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<FileInfo> getFile() throws MetaStoreException {
    updateCache();
    try {
      return fileInfoDao.getAll();
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<FileInfo> getFilesByPrefix(String path) throws MetaStoreException {
    updateCache();
    try {
      return fileInfoDao.getFilesByPrefix(path);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<FileInfo> getFilesByPrefixInOrder(String path) throws MetaStoreException {
    updateCache();
    try {
      return fileInfoDao.getFilesByPrefixInOrder(path);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<FileInfo> getFilesByPaths(Collection<String> paths)
      throws MetaStoreException {
    try {
      return fileInfoDao.getFilesByPaths(paths);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public Map<String, Long> getFileIDs(Collection<String> paths)
      throws MetaStoreException {
    try {
      return fileInfoDao.getPathFids(paths);
    } catch (EmptyResultDataAccessException e) {
      return new HashMap<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * @param srcFileId  the fid of old file.
   * @param destFileId the fid of new file that will take over the access
   *                   count of old file.
   */
  public void updateAccessCountTableFileIds(long srcFileId, long destFileId)
      throws MetaStoreException {
    if (srcFileId == destFileId) {
      return;
    }

    try {
      fileAccessDao.updateFileIds(srcFileId, destFileId);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteAllFileInfo() throws MetaStoreException {
    try {
      fileInfoDao.deleteAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteAllEcPolicies() throws MetaStoreException {
    try {
      ecDao.deleteAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertEcPolicies(List<ErasureCodingPolicyInfo> ecInfos) throws MetaStoreException {
    try {
      ecDao.insert(ecInfos);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ErasureCodingPolicyInfo> getAllEcPolicies() throws MetaStoreException {
    try {
      return ecDao.getAllEcPolicies();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteFileByPath(String path, boolean recursive) throws MetaStoreException {
    try {
      fileInfoDao.deleteByPath(path, recursive);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertUpdateStoragesTable(List<StorageCapacity> storages)
      throws MetaStoreException {
    mapStorageCapacity = null;
    try {
      storageDao.insertUpdateStoragesTable(storages);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertUpdateStoragesTable(StorageCapacity storage)
      throws MetaStoreException {
    insertUpdateStoragesTable(Collections.singletonList(storage));
  }

  public Map<String, StorageCapacity> getStorageCapacity() throws MetaStoreException {
    updateCache();

    Map<String, StorageCapacity> ret = new HashMap<>();
    Map<String, StorageCapacity> currentMapStorageCapacity = mapStorageCapacity;
    if (currentMapStorageCapacity != null) {
      for (String key : currentMapStorageCapacity.keySet()) {
        ret.put(key, currentMapStorageCapacity.get(key));
      }
    }
    return ret;
  }

  public void deleteStorage(String storageType) throws MetaStoreException {
    try {
      mapStorageCapacity = null;
      storageDao.deleteStorage(storageType);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public StorageCapacity getStorageCapacity(
      String type) throws MetaStoreException {
    updateCache();
    Map<String, StorageCapacity> currentMapStorageCapacity = mapStorageCapacity;
    while (currentMapStorageCapacity == null) {
      try {
        Thread.sleep(100);
      } catch (InterruptedException ex) {
        LOG.error(ex.getMessage());
      }
      currentMapStorageCapacity = mapStorageCapacity;
    }
    try {
      return currentMapStorageCapacity.get(type);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  private void updateCache() throws MetaStoreException {
    if (mapStoragePolicyIdName == null) {
      mapStoragePolicyNameId = null;
      try {
        mapStoragePolicyIdName = storageDao.getStoragePolicyIdNameMap();
      } catch (Exception e) {
        throw new MetaStoreException(e);
      }
      mapStoragePolicyNameId = new HashMap<>();
      for (Integer key : mapStoragePolicyIdName.keySet()) {
        mapStoragePolicyNameId.put(mapStoragePolicyIdName.get(key), key);
      }
    }

    if (mapStorageCapacity == null) {
      try {
        mapStorageCapacity = storageDao.getStorageTablesItem();
      } catch (Exception e) {
        throw new MetaStoreException(e);
      }
    }
  }

  public void insertCachedFiles(long fid, String path,
                                long fromTime,
                                long lastAccessTime, int numAccessed) throws MetaStoreException {
    try {
      cacheFileDao.insert(fid, path, fromTime, lastAccessTime, numAccessed);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertCachedFiles(List<CachedFileStatus> fileStatuses)
      throws MetaStoreException {
    try {
      cacheFileDao.insert(fileStatuses);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteAllCachedFile() throws MetaStoreException {
    try {
      cacheFileDao.deleteAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public boolean updateCachedFiles(Long fid,
                                   Long lastAccessTime,
                                   Integer numAccessed) throws MetaStoreException {
    try {
      return cacheFileDao.update(fid, lastAccessTime, numAccessed) >= 0;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateCachedFiles(Collection<AggregatedAccessCounts> accessCounts)
      throws MetaStoreException {
    try {
      cacheFileDao.update(accessCounts);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteCachedFile(long fid) throws MetaStoreException {
    try {
      cacheFileDao.deleteById(fid);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<CachedFileStatus> getCachedFileStatus() throws MetaStoreException {
    try {
      return cacheFileDao.getAll();
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<Long> getCachedFids() throws MetaStoreException {
    try {
      return cacheFileDao.getFids();
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public CachedFileStatus getCachedFileStatus(
      long fid) throws MetaStoreException {
    try {
      return cacheFileDao.getById(fid);
    } catch (NotFoundException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void execute(String sql) throws MetaStoreException {
    try {
      LOG.debug("Execute sql = {}", sql);
      metaStoreHelper.execute(sql);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  //Todo: optimize
  public void execute(List<String> statements) throws MetaStoreException {
    for (String statement : statements) {
      execute(statement);
    }
  }

  public List<String> executeFilesPathQuery(
      String sql) throws MetaStoreException {
    try {
      LOG.debug("ExecuteFilesPathQuery sql = {}", sql);
      return metaStoreHelper.getFilesPath(sql);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public boolean insertNewRule(RuleInfo info)
      throws MetaStoreException {
    try {
      return ruleDao.insert(info) >= 0;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public boolean updateRuleInfo(long ruleId, RuleState rs,
                                long lastCheckTime, long checkedCount, int commandsGen)
      throws MetaStoreException {
    try {
      if (rs == null) {
        return ruleDao.update(ruleId,
            lastCheckTime, checkedCount, commandsGen) >= 0;
      }
      return ruleDao.update(ruleId,
          rs.getValue(), lastCheckTime, checkedCount, commandsGen) >= 0;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateRuleState(long ruleId, RuleState rs)
      throws MetaStoreException {
    if (rs == null) {
      throw new MetaStoreException("Rule state can not be null, ruleId = " + ruleId);
    }
    try {
      ruleDao.update(ruleId, rs.getValue());
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public RuleInfo getRuleInfo(long ruleId) throws MetaStoreException {
    try {
      return ruleDao.getById(ruleId);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<RuleInfo> getRuleInfos() throws MetaStoreException {
    try {
      return ruleDao.getAll();
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void upsertCmdlets(List<CmdletInfo> commands)
      throws MetaStoreException {
    if (commands.isEmpty()) {
      return;
    }
    try {
      cmdletDao.upsert(commands);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertCmdlet(CmdletInfo command)
      throws MetaStoreException {
    try {
      // Update if exists
      if (getCmdletById(command.getId()) != null) {
        cmdletDao.update(command);
      } else {
        cmdletDao.insert(command);
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public long getMaxCmdletId() throws MetaStoreException {
    try {
      return cmdletDao.getMaxId();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public CmdletInfo getCmdletById(long cid) throws MetaStoreException {
    LOG.debug("Get cmdlet by cid {}", cid);
    try {
      return cmdletDao.getById(cid);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<CmdletInfo> getCmdlets(CmdletState state) throws MetaStoreException {
    try {
      return cmdletDao.getByState(state);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public boolean deleteCmdlet(long cid) throws MetaStoreException {
    try {
      return cmdletDao.delete(cid);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void batchDeleteCmdlet(List<Long> cids) throws MetaStoreException {
    try {
      cmdletDao.batchDelete(cids);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * Delete finished cmdlets before given timestamp, actions belonging to these cmdlets
   * will also be deleted. Cmdlet's generate_time is used for comparison.
   *
   * @return number of cmdlets deleted
   */
  public int deleteFinishedCmdletsWithGenTimeBefore(long timestamp) throws MetaStoreException {
    try {
      return cmdletDao.deleteBeforeTime(timestamp);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public int deleteKeepNewCmdlets(long num) throws MetaStoreException {
    try {
      return cmdletDao.deleteKeepNewCmd(num);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public long getNumCmdletsInTerminatedStates() throws MetaStoreException {
    try {
      return cmdletDao.getNumCmdletsInTerminiatedStates();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void upsertActions(List<ActionInfo> actionInfos)
      throws MetaStoreException {
    try {
      actionDao.upsert(actionInfos);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertAction(ActionInfo actionInfo)
      throws MetaStoreException {
    LOG.debug("Insert Action ID {}", actionInfo.getActionId());
    try {
      if (getActionById(actionInfo.getActionId()) != null) {
        actionDao.update(actionInfo);
      } else {
        actionDao.insert(actionInfo);
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteCmdletActions(long cmdletId) throws MetaStoreException {
    try {
      actionDao.deleteCmdletActions(cmdletId);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void batchDeleteCmdletActions(List<Long> cmdletIds) throws MetaStoreException {
    try {
      actionDao.batchDeleteCmdletActions(cmdletIds);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateActions(ActionInfo[] actionInfos)
      throws MetaStoreException {
    if (actionInfos == null || actionInfos.length == 0) {
      return;
    }
    LOG.debug("Update Action ID {}", actionInfos[0].getActionId());
    try {
      actionDao.update(actionInfos);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ActionInfo> getNewCreatedActions(
      int size) throws MetaStoreException {
    if (size < 0) {
      return new ArrayList<>();
    }
    try {
      return actionDao.getLatestActions(size);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ActionInfo> getActions(
      List<Long> aids) throws MetaStoreException {
    if (aids == null || aids.isEmpty()) {
      return new ArrayList<>();
    }
    LOG.debug("Get Action ID {}", aids);
    try {
      return actionDao.getByIds(aids);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ActionInfo> getActionsByRuleId(long rid) throws MetaStoreException {
    List<CmdletInfo> cmdletInfos = cmdletDao.getByRuleId(rid);
    List<ActionInfo> actions = new ArrayList<>();

    for (CmdletInfo cmdletInfo : cmdletInfos) {
      for (Long aid : cmdletInfo.getActionIds()) {
        ActionInfo actionInfo = getActionById(aid);
        actions.add(actionInfo);
      }
    }
    return actions;
  }

  public ActionInfo getActionById(long aid) throws MetaStoreException {
    LOG.debug("Get actioninfo by aid {}", aid);
    try {
      return actionDao.getById(aid);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }


  public long getMaxActionId() throws MetaStoreException {
    try {
      return actionDao.getMaxId();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public Integer getStoragePolicyID(
      String policyName) throws MetaStoreException {
    try {
      updateCache();
      return mapStoragePolicyNameId.get(policyName);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public long insertFileDiff(FileDiff fileDiff)
      throws MetaStoreException {
    try {
      return fileDiffDao.insert(fileDiff);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<Long> insertFileDiffs(List<FileDiff> fileDiffs)
      throws MetaStoreException {
    try {
      return fileDiffDao.insert(fileDiffs);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<FileDiff> getFileDiffsByFileName(String fileName) throws MetaStoreException {
    try {
      return fileDiffDao.getByFileName(fileName);
    } catch (EmptyResultDataAccessException e) {
      return new ArrayList<>();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }


  @Override
  public boolean updateFileDiff(long did,
                                FileDiffState state) throws MetaStoreException {
    try {
      return fileDiffDao.update(did, state) >= 0;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void batchUpdateFileDiff(
      List<Long> did, FileDiffState state)
      throws MetaStoreException {
    try {
      fileDiffDao.batchUpdate(did, state);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateFileDiff(List<FileDiff> fileDiffs)
      throws MetaStoreException {
    if (CollectionUtils.isEmpty(fileDiffs)) {
      return;
    }
    try {
      fileDiffDao.update(fileDiffs);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public int getUselessFileDiffNum() throws MetaStoreException {
    try {
      return fileDiffDao.getUselessRecordsNum();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public int deleteUselessFileDiff(int maxNumRecords) throws MetaStoreException {
    try {
      return fileDiffDao.deleteUselessRecords(maxNumRecords);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public List<FileDiff> getPendingDiff() throws MetaStoreException {
    return fileDiffDao.getPendingDiff();
  }

  public void dropAllTables() throws MetaStoreException {
    try {
      dbSchemaManager.clearDatabase();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void initializeDataBase() throws MetaStoreException {
    try {
      dbSchemaManager.initializeDatabase();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void checkTables() throws MetaStoreException {
    try {
      int num = getTablesNum(MetaStoreUtils.SSM_TABLES);
      if (num == 0) {
        LOG.info("The table set required by SSM does not exist. "
            + "The configured database will be formatted.");
        dropAllTables();
      } else if (num < MetaStoreUtils.SSM_TABLES.size()) {
        LOG.error("One or more tables required by SSM are missing! "
            + "You can restart SSM with -format option or configure another database.");
        System.exit(1);
      }
      // we should run migration tool on every launch to check if there are new changelogs
      initializeDataBase();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public int getTablesNum(List<String> tableSet) {
    return dbMetadataProvider.tablesCount(tableSet);
  }

  public boolean tableExists(String tableName) throws MetaStoreException {
    return dbMetadataProvider.tableExists(tableName);
  }

  public void formatDataBase() throws MetaStoreException {
    dropAllTables();
    initializeDataBase();
  }

  public void setClusterConfig(
      ClusterConfig clusterConfig) throws MetaStoreException {
    try {

      if (clusterConfigDao.getCountByName(clusterConfig.getNodeName()) == 0) {
        //insert
        clusterConfigDao.insert(clusterConfig);
      } else {
        //update
        clusterConfigDao.updateByNodeName(clusterConfig.getNodeName(),
            clusterConfig.getConfigPath());
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void delClusterConfig(
      ClusterConfig clusterConfig) throws MetaStoreException {
    try {
      if (clusterConfigDao.getCountByName(clusterConfig.getNodeName()) > 0) {
        //insert
        clusterConfigDao.delete(clusterConfig.getCid());
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ClusterConfig> listClusterConfig() throws MetaStoreException {
    try {
      return clusterConfigDao.getAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public GlobalConfig getDefaultGlobalConfigByName(
      String configName) throws MetaStoreException {
    try {
      if (globalConfigDao.getCountByName(configName) > 0) {
        //the property is existed
        return globalConfigDao.getByPropertyName(configName);
      } else {
        return null;
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void setGlobalConfig(
      GlobalConfig globalConfig) throws MetaStoreException {
    try {
      if (globalConfigDao.getCountByName(globalConfig.getPropertyName()) > 0) {
        globalConfigDao.update(globalConfig.getPropertyName(),
            globalConfig.getPropertyValue());
      } else {
        globalConfigDao.insert(globalConfig);
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public List<BackUpInfo> listAllBackUpInfo() throws MetaStoreException {
    try {
      return backUpInfoDao.getAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public boolean srcInBackup(String src) throws MetaStoreException {
    if (backupSourcePatterns == null) {
      backupSourcePatterns = new HashMap<>();
      listAllBackUpInfo().stream()
          .map(BackUpInfo::getSrcPattern)
          .forEach(this::addBackUpSourcePattern);
    }
    // LOG.info("Backup src = {}, setBackSrc {}", src, setBackSrc);
    for (Pattern srcPattern : backupSourcePatterns.values()) {
      if (srcPattern.matcher(src).matches()) {
        return true;
      }
    }
    return false;
  }

  @Override
  public BackUpInfo getBackUpInfo(long rid) throws MetaStoreException {
    try {
      return backUpInfoDao.getByRid(rid);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<BackUpInfo> getBackUpInfoBySrc(String src) throws MetaStoreException {
    try {
      // More than one dest may exist for one same src
      List<BackUpInfo> backUpInfos = new ArrayList<>();
      for (BackUpInfo backUpInfo : listAllBackUpInfo()) {
        if (src.startsWith(backUpInfo.getSrc())) {
          backUpInfos.add(backUpInfo);
        }
      }
      return backUpInfos;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public void deleteAllBackUpInfo() throws MetaStoreException {
    try {
      backUpInfoDao.deleteAll();
      backupSourcePatterns.clear();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public void deleteBackUpInfo(long rid) throws MetaStoreException {
    try {
      BackUpInfo backUpInfo = getBackUpInfo(rid);
      if (backUpInfo != null) {
        if (backUpInfoDao.getBySrc(backUpInfo.getSrc()).size() == 1) {
          if (backupSourcePatterns != null) {
            backupSourcePatterns.remove(backUpInfo.getSrcPattern());
          }
        }
        backUpInfoDao.delete(rid);
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public void insertBackUpInfo(
      BackUpInfo backUpInfo) throws MetaStoreException {
    try {
      backUpInfoDao.insert(backUpInfo);
      addBackUpSourcePattern(backUpInfo.getSrcPattern());
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<ClusterInfo> listAllClusterInfo() throws MetaStoreException {
    try {
      return clusterInfoDao.getAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<SystemInfo> listAllSystemInfo() throws MetaStoreException {
    try {
      return systemInfoDao.getAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public SystemInfo getSystemInfoByProperty(
      String property) throws MetaStoreException {
    try {
      return systemInfoDao.getByProperty(property);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public boolean containSystemInfo(String property) throws MetaStoreException {
    try {
      return systemInfoDao.containsProperty(property);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteAllClusterInfo() throws MetaStoreException {
    try {
      clusterInfoDao.deleteAll();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateSystemInfo(
      SystemInfo systemInfo) throws MetaStoreException {
    try {
      systemInfoDao.update(systemInfo);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void updateAndInsertIfNotExist(
      SystemInfo systemInfo) throws MetaStoreException {
    try {
      if (systemInfoDao.update(systemInfo) <= 0) {
        systemInfoDao.insert(systemInfo);
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteClusterInfo(long cid) throws MetaStoreException {
    try {
      clusterInfoDao.delete(cid);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void deleteSystemInfo(
      String property) throws MetaStoreException {
    try {
      systemInfoDao.delete(property);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertClusterInfo(
      ClusterInfo clusterInfo) throws MetaStoreException {
    try {
      if (clusterInfoDao.getCountByName(clusterInfo.getName()) != 0) {
        throw new Exception("name has already exist");
      }
      clusterInfoDao.insert(clusterInfo);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertSystemInfo(SystemInfo systemInfo)
      throws MetaStoreException {
    try {
      if (systemInfoDao.containsProperty(systemInfo.getProperty())) {
        throw new Exception("The system property already exists");
      }
      systemInfoDao.insert(systemInfo);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertUpdateFileState(FileState fileState)
      throws MetaStoreException {
    try {
      // Update corresponding tables according to the file state
      fileStateDao.insertUpdate(fileState);
      switch (fileState.getFileType()) {
        case COMPACT:
          CompactFileState compactFileState = (CompactFileState) fileState;
          smallFileDao.insertUpdate(compactFileState);
          break;
        case COMPRESSION:
          CompressionFileState compressionFileState =
              (CompressionFileState) fileState;
          compressionFileDao.insertUpdate(compressionFileState);
          break;
        case S3:
          break;
        default:
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public void insertCompactFileStates(CompactFileState[] compactFileStates)
      throws MetaStoreException {
    try {
      fileStateDao.batchInsertUpdate(compactFileStates);
      smallFileDao.batchInsertUpdate(compactFileStates);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * Get FileState of the given path.
   */
  public FileState getFileState(String path) throws MetaStoreException {
    FileState fileState;
    try {
      fileState = fileStateDao.getByPath(path);
      // Fetch info from corresponding table to regenerate a specific file state
      switch (fileState.getFileType()) {
        case NORMAL:
          fileState = new NormalFileState(path);
          break;
        case COMPACT:
          fileState = smallFileDao.getFileStateByPath(path);
          break;
        case COMPRESSION:
          CompressionFileState compressionFileState = getCompressionInfo(path);
          if (compressionFileState != null) {
            compressionFileState.setFileStage(fileState.getFileStage());
            fileState = compressionFileState;
          }
          break;
        case S3:
          fileState = new S3FileState(path);
          break;
        default:
      }
    } catch (EmptyResultDataAccessException e1) {
      fileState = new NormalFileState(path);
    } catch (Exception e2) {
      throw new MetaStoreException(e2);
    }
    return fileState;
  }

  public Map<String, FileState> getFileStates(List<String> paths)
      throws MetaStoreException {
    try {
      return fileStateDao.getByPaths(paths);
    } catch (EmptyResultDataAccessException e1) {
      return new HashMap<>();
    } catch (Exception e2) {
      throw new MetaStoreException(e2);
    }
  }

  /**
   * Delete FileState of the given fileName (including its corresponding compression/
   * compact/s3 state).
   */
  public void deleteFileState(String filePath) throws MetaStoreException {
    try {
      FileState fileState = getFileState(filePath);
      fileStateDao.deleteByPath(filePath, false);
      switch (fileState.getFileType()) {
        case COMPACT:
          smallFileDao.deleteByPath(filePath, false);
          break;
        case COMPRESSION:
          deleteCompressedFile(filePath);
          break;
        case S3:
          break;
        default:
      }
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public List<String> getSmallFilesByContainerFile(String containerFilePath)
      throws MetaStoreException {
    try {
      return smallFileDao.getSmallFilesByContainerFile(containerFilePath);
    } catch (EmptyResultDataAccessException e1) {
      return new ArrayList<>();
    } catch (Exception e2) {
      throw new MetaStoreException(e2);
    }
  }

  public List<String> getAllContainerFiles() throws MetaStoreException {
    try {
      return smallFileDao.getAllContainerFiles();
    } catch (EmptyResultDataAccessException e1) {
      return new ArrayList<>();
    } catch (Exception e2) {
      throw new MetaStoreException(e2);
    }
  }

  /**
   * Clear up FileState info from database (including all corresponding compression/
   * compact/s3 state).
   */
  public synchronized void deleteAllFileState() throws MetaStoreException {
    try {
      fileStateDao.deleteAll();
      // Delete all other states
      deleteAllCompressedFile();
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * Delete a compressed file from database.
   */
  private synchronized void deleteCompressedFile(String fileName) {
    compressionFileDao.deleteByPath(fileName);
  }

  /**
   * Delete all compressed files from database.
   */
  private synchronized void deleteAllCompressedFile() throws MetaStoreException {
    compressionFileDao.deleteAll();
  }

  /**
   * Get the compression info of a compressed info.
   */
  public synchronized CompressionFileState getCompressionInfo(
      String fileName) throws MetaStoreException {
    try {
      return compressionFileDao.getInfoByPath(fileName);
    } catch (EmptyResultDataAccessException e) {
      return null;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * Get last fetched dirs of whitelist.
   */
  public List<String> getLastFetchedDirs() throws MetaStoreException {
    try {
      List<String> lastFetchedDirs = new ArrayList<>();
      String fetchedList = whitelistDao.getLastFetchedDirs();
      if (!fetchedList.isEmpty()) {
        String[] oldList = fetchedList.split(",");
        lastFetchedDirs.addAll(Arrays.asList(oldList));
      }
      LOG.info("Last fetch dirs are " + lastFetchedDirs.toString());
      return lastFetchedDirs;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  /**
   * Update whitelist table with current whitelist configuration.
   */
  public void updateWhitelistTable(String newWhitelist) throws MetaStoreException {
    try {
      whitelistDao.updateTable(newWhitelist);
      LOG.info("Success to update whitelist table with " + newWhitelist);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  @Override
  public void close() {
    dbPool.close();
  }

  private void addBackUpSourcePattern(String sourcePattern) {
    if (backupSourcePatterns == null) {
      backupSourcePatterns = new HashMap<>();
    }
    backupSourcePatterns.put(sourcePattern, Pattern.compile(sourcePattern));
  }
}
