/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.hdfs.action;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.curator.shaded.com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.apache.hadoop.tools.DistCpOptions;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.smartdata.hdfs.MiniClusterHarness;

/**
 * Test for DistCpAction.
 * TODO: idents 2 spaces
 */
public class TestDistCpAction extends MiniClusterHarness {

    @Rule
    public TemporaryFolder tmpFolder = new TemporaryFolder();

    public DistCpAction createAction(Map<String, String> args) {
        DistCpAction distCpAction = new DistCpAction();
        distCpAction.setDfsClient(dfsClient);
        distCpAction.setContext(smartContext);
        distCpAction.init(args);
        return distCpAction;
    }

    @Test
    public void testParseSingleSource() {
        Map<String, String> args = new HashMap<>();
        args.put(DistCpAction.FILE_PATH, "/test/source/dir1");
        args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
        DistCpAction action = createAction(args);
        DistCpOptions distCpOptions = action.getOptions();

        Path expectedSource = new Path("/test/source/dir1");
        Assert.assertEquals(Collections.singletonList(expectedSource),
            distCpOptions.getSourcePaths());
        Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
            distCpOptions.getTargetPath());
    }

    @Test
    public void testParseSeveralSources() {
        Map<String, String> args = new HashMap<>();
        args.put(DistCpAction.FILE_PATH, "/test/source/dir1,/test/source/dir2,/test/source/dir3");
        args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
        DistCpAction action = createAction(args);
        DistCpOptions distCpOptions = action.getOptions();

        List<Path> expectedSources = Stream.of(
            "/test/source/dir1", "/test/source/dir2", "/test/source/dir3")
            .map(Path::new)
            .collect(Collectors.toList());
        Assert.assertEquals(expectedSources,
            distCpOptions.getSourcePaths());
        Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
            distCpOptions.getTargetPath());
    }

    @Test
    public void testParseDistCpOptionalArgs() {
        Map<String, String> args = new HashMap<>();
        args.put(DistCpAction.FILE_PATH, "/test/source/dir1");
        args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
        args.put("-pcat", "");
        args.put("-m", "16");
        args.put("-strategy", "dynamic");
        args.put("-update", "");
        DistCpAction action = createAction(args);
        DistCpOptions distCpOptions = action.getOptions();

        Path expectedSource = new Path("/test/source/dir1");
        HashSet<DistCpOptions.FileAttribute> expectedPreserveAttributes = Sets.newHashSet(
            DistCpOptions.FileAttribute.CHECKSUMTYPE,
            DistCpOptions.FileAttribute.ACL,
            DistCpOptions.FileAttribute.TIMES);

        Assert.assertEquals(Collections.singletonList(expectedSource),
            distCpOptions.getSourcePaths());
        Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
            distCpOptions.getTargetPath());
        Assert.assertEquals(expectedPreserveAttributes, distCpOptions.getPreserveAttributes());
        Assert.assertEquals(16, distCpOptions.getMaxMaps());
        Assert.assertEquals("dynamic", distCpOptions.getCopyStrategy());
        Assert.assertTrue(distCpOptions.shouldSyncFolder());
    }

    @Test
    public void testIntraClusterCopy() throws Exception {
        testCopyToCluster(dfs, dfs);
    }

    @Test
    public void testCopyToAnotherCluster() throws Exception {
        try (MiniDFSCluster anotherCluster = createAnotherCluster()) {
            anotherCluster.waitActive();
            FileSystem anotherFs = anotherCluster.getFileSystem();
            testCopyToCluster(dfs, anotherFs);
        }
    }

    @Test
    public void testCopyFromAnotherCluster() throws Exception {
        try (MiniDFSCluster anotherCluster = createAnotherCluster()) {
            anotherCluster.waitActive();
            FileSystem anotherFs = anotherCluster.getFileSystem();
            testCopyToCluster(anotherFs, dfs);
        }
    }

    private void testCopyToCluster(FileSystem sourceFs, FileSystem targetFs) throws Exception {
        Map<String, String> args = new HashMap<>();
        String sourcePath = sourceFs.getUri() + "/test/source/dir1";
        String targetPath = targetFs.getUri() + "/test/target/";

        args.put(DistCpAction.FILE_PATH, sourcePath);
        args.put(DistCpAction.TARGET_ARG, targetPath);
        DistCpAction action = createAction(args);

        writeToFile(sourceFs, new Path(sourcePath + "/testFile1"), "data-1");
        writeToFile(sourceFs, new Path(sourcePath + "/testFile2"), "another file data");
        writeToFile(sourceFs, new Path(sourcePath + "/inner/testFile3"), "inner data");

        action.execute();

        assertFileContent(targetFs, new Path(targetPath + "/dir1/testFile1"), "data-1");
        assertFileContent(targetFs, new Path(targetPath + "/dir1/testFile2"), "another file data");
        assertFileContent(targetFs, new Path(targetPath + "/dir1/inner/testFile3"), "inner data");
    }

    private MiniDFSCluster createAnotherCluster() throws Exception {
        Configuration clusterConfig = new Configuration(smartContext.getConf());
        clusterConfig.set("hdfs.minidfs.basedir", tmpFolder.newFolder().getAbsolutePath());
        return createCluster(clusterConfig);
    }

    private void assertFileContent(
        final FileSystem fileSystem, final Path path, final String expectedData) throws IOException {
        Assert.assertTrue(fileSystem.exists(path));
        Assert.assertEquals(expectedData, readFromFile(fileSystem, path));
    }

    private void writeToFile(
        final FileSystem fileSystem, final Path path, final String data) throws IOException {
        fileSystem.mkdirs(path.getParent());
        try(final FSDataOutputStream outputStream = fileSystem.create(path)) {
            outputStream.writeUTF(data);
        }
    }

    private String readFromFile(final FileSystem fileSystem, final Path path) throws IOException {
        try(final FSDataInputStream inputStream = fileSystem.open(path)) {
            return inputStream.readUTF();
        }
    }
}
