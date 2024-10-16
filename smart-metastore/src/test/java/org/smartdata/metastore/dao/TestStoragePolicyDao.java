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
import org.smartdata.model.StoragePolicy;

public class TestStoragePolicyDao extends TestDaoBase {
  private StoragePolicyDao storagePolicyDao;

  @Before
  public void initStoragePolicyDao() {
    storagePolicyDao = daoProvider.storagePolicyDao();
  }

  @Test
  public void testInsertGetStorage_policyTable() throws Exception {
    StoragePolicy storagePolicy = new StoragePolicy((byte) 1, "pName");
    storagePolicyDao.insertStoragePolicyTable(storagePolicy);

    Assert.assertTrue(storagePolicyDao.getStoragePolicyName(1).equals("pName"));

    if (!storagePolicyDao.isExist("pName") || !storagePolicyDao.isExist(1)) {
      throw new Exception("isExist() error");
    }

    if (storagePolicyDao.getStoragePolicyName(1) != "pName") {
      throw new Exception("getStoragePolicyName() error");
    }

    if (storagePolicyDao.getStorageSid("pName") != 1) {
      throw new Exception("getStorageSid() error");
    }

    storagePolicyDao.getStoragePolicyIdNameMap();
    storagePolicyDao.deleteStoragePolicy("pName");

    if (storagePolicyDao.isExist("pName")) {
      throw new Exception("deleteStoragePolicy() error");
    }
  }
}
