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
/**
 * Created by cy on 17-6-19.
 */
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
import org.smartdata.model.StorageCapacity;

import java.util.Arrays;
import java.util.List;
import java.util.Map;


public class TestStorageDao extends TestDaoBase {

  private StorageDao storageDao;

  @Before
  public void initStorageDao() {
    storageDao = daoProvider.storageDao();
  }

  @Test
  public void testInsertGetStorageTable() throws Exception {
    List<StorageCapacity> storageCapacities = Arrays.asList(
        new StorageCapacity("type1", 1L, 1L),
        new StorageCapacity("type2", 2L, 2L)
    );
    storageDao.insertUpdateStoragesTable(storageCapacities);
    Assert.assertEquals(storageCapacities.get(0), storageDao.getStorageCapacity("type1"));
    Map<String, StorageCapacity> map = storageDao.getStorageTablesItem();
    Assert.assertEquals(storageCapacities.get(1), map.get("type2"));
  }
}

