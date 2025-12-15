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
package org.apache.hadoop.fs.ozone;

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hdds.conf.ConfigurationSource;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.util.Preconditions;
import org.smartdata.client.SmartClient;
import org.smartdata.ozone.client.FileAccessReportSupport;
import org.smartdata.ozone.client.SmartOzoneClientAdapter;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.IOException;
import java.io.InputStream;

public class SmartRootedOzoneFileSystem extends RootedOzoneFileSystem {

  @Override
  protected OzoneClientAdapter createAdapter(
      ConfigurationSource conf, String omHost, int omPort) throws IOException {
    return new SmartClientAdapter(
        omHost, omPort, conf, (OzoneFSStorageStatistics) getOzoneFSOpsCountStatistics()
    );
  }

  @Slf4j
  static class SmartClientAdapter extends RootedOzoneClientAdapterImpl implements SmartOzoneClientAdapter {
    private final FileAccessReportSupport accessReportSupport;

    SmartClientAdapter(
        String omHost,
        int omPort,
        ConfigurationSource hadoopConf,
        OzoneFSStorageStatistics storageStatistics) throws IOException {
      this(omHost, omPort, hadoopConf, storageStatistics,
          new SmartClient(Preconditions.checkNotNull(OzoneConfiguration.of(hadoopConf))));
    }

    SmartClientAdapter(
        String omHost,
        int omPort,
        ConfigurationSource hadoopConf,
        OzoneFSStorageStatistics storageStatistics,
        SmartClientProtocol ssmClient) throws IOException {
      super(omHost, omPort, hadoopConf, storageStatistics);
      this.accessReportSupport = new FileAccessReportSupport(ssmClient);
    }

    @Override
    public void close() {
      try {
        super.close();
      } catch (IOException e) {
        log.error("Error closing OzoneClient", e);
      }

      try {
        accessReportSupport.close();
      } catch (IOException e) {
        log.error("Error closing SmartClient", e);
      }
    }

    @Override
    public InputStream readFile(String key) throws IOException {
      InputStream inputStream = super.readFile(key);
      accessReportSupport.reportFileAccess(key);
      return inputStream;
    }

    @Override
    public String getBasePath() {
      return accessReportSupport.getBasePath();
    }
  }
}
