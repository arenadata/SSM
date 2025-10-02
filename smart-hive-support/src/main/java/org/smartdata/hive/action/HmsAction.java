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
package org.smartdata.hive.action;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.StorageDescriptor;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageDeserializer;
import org.apache.hadoop.hive.metastore.messaging.MessageFactory;
import org.smartdata.action.SmartAction;

import java.util.Optional;
import java.util.function.Supplier;

@Setter
public abstract class HmsAction extends SmartAction {
  public static final String DEST = "-dest";
  public static final String NAMESERVICE_RENAME = "-nameservice_rename";
  public static final String EVENT_MESSAGE = "-message";
  public static final String CASCADE = "-cascade";

  // IMetaStoreClient is not thread-safe and therefore the default
  // cache-based MetaStoreClientProvider uses thread id as a part of a composite cache key.
  // So we have to use supplier here instead of a client itself to get the client for
  // the thread that executes the current action.
  protected Supplier<IMetaStoreClient> metastoreClientSupplier;
  @Getter(lazy = true)
  private final IMetaStoreClient metastoreClient = metastoreClientSupplier.get();

  protected MessageDeserializer messageDeserializer;

  @Override
  protected void preRun() throws Exception {
    super.preRun();
    this.messageDeserializer = MessageFactory
        .getDefaultInstance(getContext().getConf())
        .getDeserializer();
  }

  @SuppressWarnings("unchecked")
  protected <T extends EventMessage> T parseEventMessage(EventMessage.EventType hiveEventType) {
    return (T) messageDeserializer.getEventMessage(
        hiveEventType.toString(),
        getEventMessage()
    );
  }

  protected boolean isCascade() {
    return getArguments().containsKey(CASCADE);
  }

  protected String renameNameService(String oldLocation) {
    Pair<String, String> nameServices = nameServiceToRename();
    return oldLocation.replace(nameServices.getLeft(), nameServices.getRight());
  }

  protected void renameNameService(StorageDescriptor storageDescriptor) {
    storageDescriptor.setLocation(
        renameNameService(storageDescriptor.getLocation())
    );
  }

  protected Pair<String, String> nameServiceToRename() {
    return Optional.ofNullable(getArguments().get(NAMESERVICE_RENAME))
        .map(str -> str.split(" "))
        .filter(names -> names.length != 2)
        .map(names -> ImmutablePair.of(names[0], names[1]))
        .orElseThrow(() -> new IllegalArgumentException(
            "Wrong format of `-nameservice_rename` argument"));
  }

  private String getEventMessage() {
    return Optional.ofNullable(getArguments().get(EVENT_MESSAGE))
        .orElseThrow(() -> new IllegalArgumentException("No event message provided"));
  }
}
