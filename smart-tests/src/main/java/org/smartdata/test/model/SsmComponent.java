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
package org.smartdata.test.model;

import io.arenadata.test.model.Component;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;

@Getter
@AllArgsConstructor
public enum SsmComponent implements Component {
  HADOOP_NAMENODE("hadoop-namenode", 8020),
  HADOOP_DATANODE("hadoop-datanode", 7051),
  SSM_SERVER("ssm-server", 8081),
  SSM_METASTORE_DB("ssm-metastore-db", 5432),
  KDC_SERVER("kdc-server", 749),
  SAMBA("samba", 389),
  HIVE_SERVER_2("hive-server2", 10000),
  HIVE_METASTORE("hive-metastore", 9083),
  TARGET_NAMENODE("target-namenode", 0),
  TARGET_DATANODE("target-datanode", 0),
  TARGET_HIVE_METASTORE("target-hive-metastore", 0),
  TARGET_HIVE_SERVER2("target-hive-server2", 0),
  PROMETHEUS("prometheus", 9090);

  private final String name;
  private final int port;

  private static final List<Component> DEFAULT_COMPONENTS = Arrays.asList(
      HADOOP_NAMENODE,
      HADOOP_DATANODE,
      SSM_SERVER,
      SSM_METASTORE_DB,
      KDC_SERVER,
      SAMBA,
      HIVE_SERVER_2,
      HIVE_METASTORE,
      PROMETHEUS
  );

  private static final List<Component> HMS_COMPONENTS = Arrays.asList(
      HADOOP_NAMENODE,
      HADOOP_DATANODE,
      SSM_SERVER,
      SSM_METASTORE_DB,
      HIVE_SERVER_2,
      HIVE_METASTORE,
      TARGET_NAMENODE,
      TARGET_DATANODE,
      TARGET_HIVE_METASTORE,
      TARGET_HIVE_SERVER2
  );

  public static SsmComponent fromName(String name) {
    return SsmComponent.valueOf(name.toUpperCase().replace("-", "_"));
  }

  public static List<Component> getComponentsByCompose(String composeName) {
    if (composeName.contains("multihost")) {
      return DEFAULT_COMPONENTS;
    } else if (composeName.contains("demo-cluster")) {
      return HMS_COMPONENTS;
    } else {
      throw new IllegalArgumentException("Unknown compose name: " + composeName);
    }
  }
}
