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
package org.smartdata.hive.action.db;

import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.messaging.DropDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;
import org.junit.Test;
import org.smartdata.hive.NotificationEventFactory;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.smartdata.hive.action.HmsAction.CASCADE;
import static org.smartdata.hive.action.HmsAction.DEST;
import static org.smartdata.hive.action.HmsAction.EVENT_MESSAGE;
import static org.smartdata.hive.action.HmsAction.EVENT_MESSAGE_FORMAT;

public class HmsDropDbActionTest {

  @Test
  public void testSkipTargetDropIfSourceDatabaseStillExists() throws Exception {
    IMetaStoreClient targetMetastoreClient = mock(IMetaStoreClient.class);
    HmsDropDbAction action = new StubHmsDropDbAction(true);
    action.setMetastoreClientSupplier(() -> targetMetastoreClient);
    action.init(actionArgs(dropDbEvent(), true));

    action.run();

    verify(targetMetastoreClient, never())
        .dropDatabase("db1", false, false, true);
    assertTrue(action.getExpectedAfterRun());
  }

  @Test
  public void testDropTargetIfSourceDatabaseDoesNotExist() throws Exception {
    IMetaStoreClient targetMetastoreClient = mock(IMetaStoreClient.class);
    HmsDropDbAction action = new StubHmsDropDbAction(false);
    action.setMetastoreClientSupplier(() -> targetMetastoreClient);
    action.init(actionArgs(dropDbEvent(), true));

    action.run();

    verify(targetMetastoreClient)
        .dropDatabase("db1", false, false, true);
    assertTrue(action.getExpectedAfterRun());
  }

  private static NotificationEvent dropDbEvent() {
    return NotificationEventFactory.newDropDbEvent(1L, "hive.db1", "/warehouse/db1");
  }

  private static Map<String, String> actionArgs(NotificationEvent event, boolean withCascade) {
    Map<String, String> args = new HashMap<>();
    args.put(DEST, "thrift://target-hive-metastore:9083/");
    args.put(EVENT_MESSAGE, event.getMessage());
    args.put(EVENT_MESSAGE_FORMAT, new JSONMessageEncoder().getMessageFormat());
    if (withCascade) {
      args.put(CASCADE, "");
    }
    return args;
  }

  private static class StubHmsDropDbAction extends HmsDropDbAction {
    private final boolean sourceDatabaseExists;

    private StubHmsDropDbAction(boolean sourceDatabaseExists) {
      this.sourceDatabaseExists = sourceDatabaseExists;
    }

    @Override
    protected boolean sourceDatabaseExists(DropDatabaseMessage message) {
      return sourceDatabaseExists;
    }
  }
}
