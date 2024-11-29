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
package org.smartdata.metastore.dao;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.FileInfo;

import java.util.List;

public class TestFileInfoDao extends TestDaoBase {
  private FileInfoDao fileInfoDao;

  @Before
  public void initFileDao() {
    fileInfoDao = daoProvider.fileInfoDao();
  }

  @Test
  public void testInsetGetDeleteFiles() {
    String path = "/testFile";
    long length = 123L;
    boolean isDir = false;
    short blockReplication = 1;
    long blockSize = 128 * 1024L;
    long modTime = 123123123L;
    long accessTime = 123123120L;
    short permission = 1;
    String owner = "root";
    String group = "admin";
    long fileId = 1L;
    byte storagePolicy = 0;
    byte erasureCodingPolicy = 0;
    FileInfo fileInfo = new FileInfo(path, fileId, length, isDir, blockReplication, blockSize,
        modTime, accessTime, permission, owner, group, storagePolicy, erasureCodingPolicy);
    fileInfoDao.insert(fileInfo, true);

    FileInfo file1 = fileInfoDao.getByPath("/testFile");
    Assert.assertEquals(fileInfo, file1);

    FileInfo file2 = fileInfoDao.getById(fileId);
    Assert.assertEquals(fileInfo, file2);

    FileInfo fileInfo1 = new FileInfo(path, fileId + 1, length, isDir, blockReplication, blockSize,
        modTime, accessTime, permission, owner, group, storagePolicy, erasureCodingPolicy);
    fileInfoDao.insert(fileInfo1, true);
    List<FileInfo> fileInfos = fileInfoDao.getFilesByPrefix("/testaaFile");
    Assert.assertEquals(0, fileInfos.size());

    fileInfos = fileInfoDao.getFilesByPrefix("/testFile");
    Assert.assertEquals(2, fileInfos.size());

    fileInfoDao.deleteById(fileId);
    fileInfos = fileInfoDao.getAll();
    Assert.assertEquals(1, fileInfos.size());

    fileInfoDao.deleteAll();
    fileInfos = fileInfoDao.getAll();
    Assert.assertTrue(fileInfos.isEmpty());
  }

  @Test
  public void testInsertUpdateFiles() {
    String path = "/testFile";
    long length = 123L;
    boolean isDir = false;
    short blockReplication = 1;
    long blockSize = 128 * 1024L;
    long modTime = 123123123L;
    long accessTime = 123123120L;
    short permission = 1;
    String owner = "root";
    String group = "admin";
    long fileId = 1L;
    byte storagePolicy = 0;
    byte erasureCodingPolicy = 0;

    FileInfo fileInfo = new FileInfo(path, fileId, length, isDir, blockReplication, blockSize,
        modTime, accessTime, permission, owner, group, storagePolicy, erasureCodingPolicy);
    fileInfoDao.insert(fileInfo, true);
    fileInfoDao.update(path, 10);
    FileInfo file = fileInfoDao.getById(fileId);
    fileInfo.setStoragePolicy((byte) 10);

    Assert.assertEquals(file, fileInfo);
  }
}
