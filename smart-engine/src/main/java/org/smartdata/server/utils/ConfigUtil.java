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
package org.smartdata.server.utils;

import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.conf.SmartFsType;
import org.smartdata.hdfs.HadoopUtil;

import java.io.IOException;
import java.net.URL;
import java.util.Optional;

import static org.apache.hadoop.fs.FileSystem.FS_DEFAULT_NAME_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_OZONE_RPC_SERVER_KEY;
import static org.smartdata.hdfs.HadoopUtil.getHadoopConfDir;
import static org.smartdata.hdfs.HadoopUtil.loadResourceSafely;
import static org.smartdata.ozone.OzoneSmartConf.getOzoneDefaultFsUri;

public class ConfigUtil {
  public static void enrichSmartConf(SmartConf conf) throws IOException {
    if (conf.getFsType() == SmartFsType.HDFS) {
      HadoopUtil.setSmartConfByHadoop(conf);
    } else {
      enrichWithOzoneConfigs(conf);
    }
    conf.set(FS_DEFAULT_NAME_KEY, conf.getDefaultFs());
  }

  public static void enrichWithOzoneConfigs(SmartConf conf) throws IOException {
    String hadoopConfPath = conf.get(SmartConfKeys.SMART_HADOOP_CONF_DIR_KEY);
    Optional<URL> hadoopConfDir = getHadoopConfDir(hadoopConfPath);
    if (!hadoopConfDir.isPresent()) {
      return;
    }

    loadResourceSafely(conf, hadoopConfDir.get(), "core-site.xml");
    loadResourceSafely(conf, hadoopConfDir.get(), "ozone-default.xml");
    loadResourceSafely(conf, hadoopConfDir.get(), "ozone-site.xml");
    String ozoneRpcAddress = getOzoneDefaultFsUri(conf).toString();
    conf.set(SMART_OZONE_RPC_SERVER_KEY, ozoneRpcAddress);
  }
}
