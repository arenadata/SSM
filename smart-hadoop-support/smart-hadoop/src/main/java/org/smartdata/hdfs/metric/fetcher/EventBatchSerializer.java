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

import org.apache.commons.collections.CollectionUtils;
import org.apache.hadoop.hdfs.inotify.EventBatch;
import org.apache.hadoop.hdfs.inotify.EventBatchList;
import org.apache.hadoop.hdfs.protocol.proto.ClientNamenodeProtocolProtos;
import org.apache.hadoop.hdfs.protocolPB.PBHelperClient;

import java.io.IOException;
import java.util.Collections;

// TODO: do we really need to (de-)serialize INotify events locally?
public class EventBatchSerializer {
  public static byte[] serialize(EventBatch eventBatch) {
    long txId = eventBatch.getTxid();
    EventBatchList batch = new EventBatchList(
        Collections.singletonList(eventBatch), txId, txId, txId);

    return PBHelperClient.convertEditsResponse(batch)
        .toByteArray();
  }

  public static EventBatch deserialize(byte[] bytes) throws IOException {
    ClientNamenodeProtocolProtos.GetEditsFromTxidResponseProto proto =
        ClientNamenodeProtocolProtos.GetEditsFromTxidResponseProto.parseFrom(bytes);

    EventBatchList eventBatchList = PBHelperClient.convert(proto);
    if (CollectionUtils.isEmpty(eventBatchList.getBatches())) {
      throw new IllegalArgumentException("Event batch list shouldn't be null");
    }

    return eventBatchList.getBatches()
        .stream()
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Event batch list shouldn't be empty"));
  }
}
