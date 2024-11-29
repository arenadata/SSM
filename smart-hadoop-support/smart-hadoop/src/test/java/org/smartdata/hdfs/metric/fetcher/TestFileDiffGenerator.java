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

import com.google.common.collect.ImmutableMap;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.inotify.Event;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hdfs.action.CopyFileAction;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.BackUpInfo;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffState;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.FileInfo;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.apache.hadoop.hdfs.inotify.Event.MetadataUpdateEvent.MetadataType.OWNER;
import static org.apache.hadoop.hdfs.inotify.Event.MetadataUpdateEvent.MetadataType.PERMS;
import static org.apache.hadoop.hdfs.inotify.Event.MetadataUpdateEvent.MetadataType.REPLICATION;
import static org.apache.hadoop.hdfs.inotify.Event.MetadataUpdateEvent.MetadataType.TIMES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.smartdata.action.SyncAction.BASE_OPERATION;
import static org.smartdata.action.SyncAction.DEST;
import static org.smartdata.hdfs.action.MetaDataAction.BLOCK_REPLICATION;
import static org.smartdata.hdfs.action.MetaDataAction.GROUP_NAME;
import static org.smartdata.hdfs.action.MetaDataAction.MTIME;
import static org.smartdata.hdfs.action.MetaDataAction.OWNER_NAME;
import static org.smartdata.hdfs.action.MetaDataAction.PERMISSION;

public class TestFileDiffGenerator extends TestDaoBase {

  private FileDiffGenerator fileDiffGenerator;

  @Before
  public void init() throws Exception {
    fileDiffGenerator = new FileDiffGenerator(metaStore, () -> 0L);

    BackUpInfo backUpInfo = new BackUpInfo(-1, "/backup/src", "/dest", 1000L);
    metaStore.insertBackUpInfo(backUpInfo);
  }

  @Test
  public void testCreateFile() throws Exception {
    FileInfo file = FileInfo.builder()
        .setPath("/backup/src/file")
        .setLength(42)
        .build();

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileCreate(file);

    Map<String, String> expectedParameters = ImmutableMap.of(
        CopyFileAction.OFFSET_INDEX, "0",
        CopyFileAction.LENGTH, "42"
    );

    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/file")
        .diffType(FileDiffType.APPEND)
        .parameters(expectedParameters)
        .build();

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  @Test
  public void testCreateDirectory() throws Exception {
    FileInfo file = FileInfo.builder()
        .setPath("/backup/src/1/dir")
        .setIsDir(true)
        .build();

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileCreate(file);
    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/1/dir")
        .diffType(FileDiffType.MKDIR)
        .build();

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  @Test
  public void testSkipCreateEventIfNotInBackupDir() throws Exception {
    FileInfo file = FileInfo.builder()
        .setPath("/another/src/1")
        .build();

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileCreate(file);
    assertFalse(fileDiff.isPresent());
  }

  @Test
  public void testCloseNewFile() throws Exception {
    Event.CloseEvent closeEvent =
        new Event.CloseEvent("/backup/src/file", 100, 1L);

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileClose(closeEvent);

    Map<String, String> expectedParameters = ImmutableMap.of(
        CopyFileAction.OFFSET_INDEX, "0",
        CopyFileAction.LENGTH, "100"
    );
    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/file")
        .diffType(FileDiffType.APPEND)
        .parameters(expectedParameters)
        .build();

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  @Test
  public void testCloseExistingFile() throws Exception {
    Event.CloseEvent closeEvent =
        new Event.CloseEvent("/backup/src/file", 100, 1L);

    FileInfo fileInfo = FileInfo.builder()
        .setPath("/backup/src/file")
        .setLength(20)
        .build();
    metaStore.insertFile(fileInfo, true);

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileClose(closeEvent);

    Map<String, String> expectedParameters = ImmutableMap.of(
        CopyFileAction.OFFSET_INDEX, "20",
        CopyFileAction.LENGTH, "80"
    );
    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/file")
        .diffType(FileDiffType.APPEND)
        .parameters(expectedParameters)
        .build();

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  @Test
  public void testSkipCloseEventIfEqualFileLength() throws Exception {
    Event.CloseEvent closeEvent =
        new Event.CloseEvent("/backup/src/file", 20, 1L);

    FileInfo fileInfo = FileInfo.builder()
        .setPath("/backup/src/file")
        .setLength(20)
        .build();
    metaStore.insertFile(fileInfo, true);

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileClose(closeEvent);
    assertFalse(fileDiff.isPresent());
  }

  @Test
  public void testSkipCloseEventIfNotInBackupDir() throws Exception {
    Event.CloseEvent closeEvent =
        new Event.CloseEvent("/another/src/file", 20, 1L);

    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileClose(closeEvent);
    assertFalse(fileDiff.isPresent());
  }

  @Test
  public void testDeleteFile() throws Exception {
    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileDelete("/backup/src/file");

    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/file")
        .diffType(FileDiffType.DELETE)
        .build();

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  @Test
  public void testSkipDeleteEventIfNotInBackupDir() throws Exception {
    Optional<FileDiff> fileDiff = fileDiffGenerator.onFileDelete("/dir/file");
    assertFalse(fileDiff.isPresent());
  }

  @Test
  public void testChangeFileTimes() throws Exception {
    Event.MetadataUpdateEvent metadataUpdateEvent = updateMetadataEvent(TIMES);

    Map<String, String> expectedParameters = ImmutableMap.of(
        MTIME, "1"
    );

    testChangeFileMetadata(metadataUpdateEvent, expectedParameters);
  }

  @Test
  public void testChangeFileReplication() throws Exception {
    Event.MetadataUpdateEvent metadataUpdateEvent = updateMetadataEvent(REPLICATION);

    Map<String, String> expectedParameters = ImmutableMap.of(
        BLOCK_REPLICATION, "42"
    );

    testChangeFileMetadata(metadataUpdateEvent, expectedParameters);
  }

  @Test
  public void testChangeFileOwnerGroup() throws Exception {
    Event.MetadataUpdateEvent metadataUpdateEvent = updateMetadataEvent(OWNER);

    Map<String, String> expectedParameters = ImmutableMap.of(
        OWNER_NAME, "newOwner",
        GROUP_NAME, "newGroup"
    );

    testChangeFileMetadata(metadataUpdateEvent, expectedParameters);
  }

  @Test
  public void testChangeFilePermissions() throws Exception {
    Event.MetadataUpdateEvent metadataUpdateEvent = updateMetadataEvent(PERMS);

    Map<String, String> expectedParameters = ImmutableMap.of(
        PERMISSION, "777"
    );

    testChangeFileMetadata(metadataUpdateEvent, expectedParameters);
  }

  @Test
  public void testSkipUpdateMetadataEventIfNotInBackupDir() throws Exception {
    Event.MetadataUpdateEvent event = new Event.MetadataUpdateEvent.Builder()
        .metadataType(OWNER)
        .path("/test")
        .build();

    Optional<FileDiff> fileDiff = fileDiffGenerator.onMetadataUpdate(event);
    assertFalse(fileDiff.isPresent());
  }

  @Test
  public void testRenameDir() throws Exception {
    createFilesForRename();

    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/backup/src/dir")
        .dstPath("/backup/src/second_dir")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));

    List<FileDiff> expectedFileDiffs = Arrays.asList(
        fileDiffBuilder("/backup/src/dir")
            .diffType(FileDiffType.RENAME)
            .parameters(ImmutableMap.of(
                DEST, "/backup/src/second_dir",
                BASE_OPERATION, ""
            ))
            .build(),
        fileDiffBuilder("/backup/src/dir/1")
            .diffType(FileDiffType.RENAME)
            .parameters(ImmutableMap.of(DEST, "/backup/src/second_dir/1"))
            .build(),
        fileDiffBuilder("/backup/src/dir/2")
            .diffType(FileDiffType.RENAME)
            .parameters(ImmutableMap.of(DEST, "/backup/src/second_dir/2"))
            .build()
    );

    assertEquals(expectedFileDiffs, fileDiffs);
  }

  @Test
  public void testRenameFile() throws Exception {
    createFilesForRename();

    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/backup/src/3")
        .dstPath("/backup/src/4")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));

    List<FileDiff> expectedFileDiffs = Collections.singletonList(
        fileDiffBuilder("/backup/src/3")
            .diffType(FileDiffType.RENAME)
            .parameters(ImmutableMap.of(
                DEST, "/backup/src/4",
                BASE_OPERATION, ""
            ))
            .build()
    );

    assertEquals(expectedFileDiffs, fileDiffs);
  }

  @Test
  public void testRenameFileDestNotInBackup() throws Exception {
    createFilesForRename();

    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/backup/src/dir")
        .dstPath("/somewhere")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));

    List<FileDiff> expectedFileDiffs = Collections.singletonList(
        fileDiffBuilder("/backup/src/dir")
            .diffType(FileDiffType.DELETE)
            .parameters(ImmutableMap.of(BASE_OPERATION, ""))
            .build()
    );

    assertEquals(expectedFileDiffs, fileDiffs);
  }

  @Test
  public void testRenameSrcDirNotInBackup() throws Exception {
    createFilesForRename();

    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/another_dir/dir")
        .dstPath("/backup/src/renamed")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));

    Map<String, String> appendParameters = ImmutableMap.of(
        CopyFileAction.OFFSET_INDEX, "0",
        CopyFileAction.LENGTH, "128"
    );

    List<FileDiff> expectedFileDiffs = Arrays.asList(
        fileDiffBuilder("/backup/src/renamed")
            .diffType(FileDiffType.MKDIR)
            .parameters(ImmutableMap.of(BASE_OPERATION, ""))
            .build(),
        fileDiffBuilder("/backup/src/renamed/4")
            .diffType(FileDiffType.APPEND)
            .parameters(appendParameters)
            .build(),
        fileDiffBuilder("/backup/src/renamed/5")
            .diffType(FileDiffType.APPEND)
            .parameters(appendParameters)
            .build()
    );

    assertEquals(expectedFileDiffs, fileDiffs);
  }

  @Test
  public void testRenameSrcFileNotInBackup() throws Exception {
    createFilesForRename();

    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/another_dir/file")
        .dstPath("/backup/src/file")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));

    List<FileDiff> expectedFileDiffs = Collections.singletonList(
        fileDiffBuilder("/backup/src/file")
            .diffType(FileDiffType.APPEND)
            .parameters(ImmutableMap.of(
                BASE_OPERATION, "",
                CopyFileAction.OFFSET_INDEX, "0",
                CopyFileAction.LENGTH, "128"
            ))
            .build()
    );

    assertEquals(expectedFileDiffs, fileDiffs);
  }


  @Test
  public void testSkipRenameEventIfNotInBackupDir() throws Exception {
    Event.RenameEvent renameEvent = new Event.RenameEvent.Builder()
        .srcPath("/another_dir/file")
        .dstPath("/another_dir/another_file")
        .build();

    List<FileDiff> fileDiffs = fileDiffGenerator.onFileRename(
        renameEvent, metaStore.getFile(renameEvent.getSrcPath()));
    assertTrue(fileDiffs.isEmpty());
  }

  private void createFilesForRename() {
    Stream.of(
        "/backup",
        "/backup/src",
        "/backup/src/dir",
        "/another_dir",
        "/another_dir/dir"
    ).forEach(path -> createFile(path, true));

    Stream.of(
        "/backup/src/dir/1",
        "/backup/src/dir/2",
        "/backup/src/3",
        "/another_dir/dir/4",
        "/another_dir/dir/5",
        "/another_dir/file"
    ).forEach(path -> createFile(path, false));
  }

  private void createFile(String path, boolean isDir) {
    FileInfo fileInfo = FileInfo.builder()
        .setPath(path)
        .setIsDir(isDir)
        .setLength(128)
        .build();
    try {
      metaStore.insertFile(fileInfo, true);
    } catch (MetaStoreException e) {
      Assert.fail(e.getMessage());
    }
  }

  private void testChangeFileMetadata(
      Event.MetadataUpdateEvent event, Map<String, String> expectedParameters) throws MetaStoreException {
    FileDiff expectedFileDiff = fileDiffBuilder("/backup/src/2/file")
        .diffType(FileDiffType.METADATA)
        .parameters(expectedParameters)
        .build();

    Optional<FileDiff> fileDiff = fileDiffGenerator.onMetadataUpdate(event);

    assertTrue(fileDiff.isPresent());
    assertEquals(expectedFileDiff, fileDiff.get());
  }

  private Event.MetadataUpdateEvent updateMetadataEvent(
      Event.MetadataUpdateEvent.MetadataType metadataType) {
    return new Event.MetadataUpdateEvent.Builder()
        .metadataType(metadataType)
        .path("/backup/src/2/file")
        .ownerName("newOwner")
        .groupName("newGroup")
        .mtime(1)
        .atime(2)
        .replication(42)
        .perms(new FsPermission(777))
        .build();
  }

  private FileDiff.Builder fileDiffBuilder(String src) {
    return FileDiff.builder()
        .src(src)
        .state(FileDiffState.PENDING)
        .createTime(0L)
        .parameters(new HashMap<>());
  }
}
