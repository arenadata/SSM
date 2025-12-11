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
package org.smartdata.ozone.client;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.fs.FileChecksum;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.SafeModeAction;
import org.apache.hadoop.fs.ozone.BasicKeyInfo;
import org.apache.hadoop.fs.ozone.FileStatusAdapter;
import org.apache.hadoop.fs.ozone.OzoneClientAdapter;
import org.apache.hadoop.fs.ozone.OzoneFSDataStreamOutput;
import org.apache.hadoop.fs.ozone.OzoneFSOutputStream;
import org.apache.hadoop.hdfs.protocol.SnapshotDiffReport;
import org.apache.hadoop.ozone.OzoneFsServerDefaults;
import org.apache.hadoop.ozone.om.helpers.LeaseKeyInfo;
import org.apache.hadoop.ozone.om.helpers.OmKeyArgs;
import org.apache.hadoop.ozone.om.helpers.OmKeyLocationInfo;
import org.apache.hadoop.ozone.security.OzoneTokenIdentifier;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.util.Preconditions;
import org.smartdata.client.SmartClient;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import static org.smartdata.utils.SecurityUtil.getCurrentUsername;

@Slf4j
public class SmartOzoneClientAdapter implements OzoneClientAdapter {
  private final OzoneClientAdapter delegate;

  private final SmartClientProtocol ssmClient;

  @Getter
  private final String basePath;

  private SmartOzoneClientAdapter(
      OzoneClientAdapter delegate,
      Configuration configuration,
      String... basePathSegments) throws IOException {
    this(delegate,
        new SmartClient(Preconditions.checkNotNull(configuration)),
        basePathSegments);
  }

  SmartOzoneClientAdapter(
      OzoneClientAdapter delegate,
      SmartClientProtocol ssmClient,
      String... basePathSegments) {
    this.delegate = Preconditions.checkNotNull(delegate);
    this.ssmClient = ssmClient;
    this.basePath = Arrays.stream(basePathSegments)
        .collect(Collectors.joining("/", "/", ""));
  }

  @Override
  public short getDefaultReplication() {
    return delegate.getDefaultReplication();
  }

  @Override
  public void close() {
    try {
      delegate.close();
    } catch (IOException e) {
      log.error("Error closing OzoneClientAdapter", e);
    }

    try {
      ssmClient.close();
    } catch (IOException e) {
      log.error("Error closing SmartClient", e);
    }
  }

  @Override
  public InputStream readFile(String key) throws IOException {
    InputStream inputStream = delegate.readFile(key);
    reportFileAccess(key);
    return inputStream;
  }

  @Override
  public OzoneFSOutputStream createFile(String key, short replication,
      boolean overWrite, boolean recursive) throws IOException {
    return delegate.createFile(key, replication, overWrite, recursive);
  }

  @Override
  public OzoneFSDataStreamOutput createStreamFile(String key, short replication,
      boolean overWrite, boolean recursive) throws IOException {
    return delegate.createStreamFile(key, replication, overWrite, recursive);
  }

  @Override
  public void renameKey(String key, String newKeyName) throws IOException {
    delegate.renameKey(key, newKeyName);
  }

  @Override
  public void rename(String pathStr, String newPath) throws IOException {
    delegate.rename(pathStr, newPath);
  }

  @Override
  public boolean createDirectory(String keyName) throws IOException {
    return delegate.createDirectory(keyName);
  }

  @Override
  public boolean deleteObject(String keyName) throws IOException {
    return delegate.deleteObject(keyName);
  }

  @Override
  public boolean deleteObject(String keyName, boolean recursive)
      throws IOException {
    return delegate.deleteObject(keyName, recursive);
  }

  @Override
  public boolean deleteObjects(List<String> keyNameList) {
    return delegate.deleteObjects(keyNameList);
  }

  @Override
  public FileStatusAdapter getFileStatus(String key, URI uri,
      Path qualifiedPath, String userName)
      throws IOException {
    return delegate.getFileStatus(key, uri, qualifiedPath, userName);
  }

  @Override
  public Iterator<BasicKeyInfo> listKeys(String pathKey) throws IOException {
    return delegate.listKeys(pathKey);
  }

  @Override
  public List<FileStatusAdapter> listStatus(String keyName, boolean recursive,
      String startKey, long numEntries, URI uri,
      Path workingDir, String username, boolean lite) throws IOException {
    return delegate.listStatus(keyName, recursive, startKey, numEntries, uri, workingDir, username, lite);
  }

  @Override
  public Token<OzoneTokenIdentifier> getDelegationToken(String renewer)
      throws IOException {
    return delegate.getDelegationToken(renewer);
  }

  @Override
  public OzoneFsServerDefaults getServerDefaults() throws IOException {
    return delegate.getServerDefaults();
  }

  @Override
  public KeyProvider getKeyProvider() throws IOException {
    return delegate.getKeyProvider();
  }

  @Override
  public URI getKeyProviderUri() throws IOException {
    return delegate.getKeyProviderUri();
  }

  @Override
  public String getCanonicalServiceName() {
    return delegate.getCanonicalServiceName();
  }

  @Override
  public boolean isFSOptimizedBucket() {
    return delegate.isFSOptimizedBucket();
  }

  @Override
  public FileChecksum getFileChecksum(String keyName, long length)
      throws IOException {
    return delegate.getFileChecksum(keyName, length);
  }

  @Override
  public String createSnapshot(String pathStr, String snapshotName)
      throws IOException {
    return delegate.createSnapshot(pathStr, snapshotName);
  }

  @Override
  public void renameSnapshot(String pathStr, String snapshotOldName, String snapshotNewName)
      throws IOException {
    delegate.renameSnapshot(pathStr, snapshotOldName, snapshotNewName);
  }

  @Override
  public void deleteSnapshot(String pathStr, String snapshotName)
      throws IOException {
    delegate.deleteSnapshot(pathStr, snapshotName);
  }

  @Override
  public SnapshotDiffReport getSnapshotDiffReport(Path snapshotDir,
      String fromSnapshot, String toSnapshot)
      throws IOException, InterruptedException {
    return delegate.getSnapshotDiffReport(snapshotDir, fromSnapshot, toSnapshot);
  }

  @Override
  public LeaseKeyInfo recoverFilePrepare(final String pathStr, boolean force) throws IOException {
    return delegate.recoverFilePrepare(pathStr, force);
  }

  @Override
  public void recoverFile(OmKeyArgs keyArgs) throws IOException {
    delegate.recoverFile(keyArgs);
  }

  @Override
  public long finalizeBlock(OmKeyLocationInfo block) throws IOException {
    return delegate.finalizeBlock(block);
  }

  @Override
  public void setTimes(String key, long mtime, long atime) throws IOException {
    delegate.setTimes(key, mtime, atime);
  }

  @Override
  public boolean isFileClosed(String pathStr) throws IOException {
    return delegate.isFileClosed(pathStr);
  }

  @Override
  public boolean setSafeMode(SafeModeAction action, boolean isChecked)
      throws IOException {
    return delegate.setSafeMode(action, isChecked);
  }

  private void reportFileAccess(String path) {
    String pathWithoutAuthority = new Path(basePath, path)
        .toUri()
        .getPath();

    FileAccessEvent accessEvent = new FileAccessEvent(
        pathWithoutAuthority,
        getCurrentUsername().orElse(null));

    try {
      ssmClient.reportFileAccessEvent(accessEvent);
    } catch (IOException exception) {
      // todo add retry mechanism for both HDFS and Ozone clients
      log.error("Error reporting file access event", exception);
    }
  }

  public static SmartOzoneClientAdapter wrap(
      OzoneClientAdapter delegate,
      Configuration configuration,
      String... basePathSegments) throws IOException {
    return new SmartOzoneClientAdapter(delegate, configuration, basePathSegments);
  }
}