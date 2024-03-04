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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.mapreduce.Cluster;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.tools.DistCp;
import org.apache.hadoop.tools.DistCpOptions;
import org.apache.hadoop.tools.OptionsParser;
import org.smartdata.action.Utils;
import org.smartdata.action.annotation.ActionSignature;

@ActionSignature(
    actionId = "distcp",
    displayName = "DistCp",
    usage = DistCpAction.FILE_PATH + " $path "
        + DistCpAction.TARGET_ARG + " $target "
        + " [additional options from "
        + "https://hadoop.apache.org/docs/stable/hadoop-distcp/DistCp.html#Command_Line_Options]"
)
public class DistCpAction extends HdfsAction {

  public static final String TARGET_ARG = "-target";
  public static final String SOURCE_PATH_LIST_FILE = "-f";

  // preserve file owner, group and permissions by default
  private static final String PRESERVE_DISTCP_OPTION_DEFAULT = "-pugp";
  private static final String SOURCE_PATHS_DELIMITER = ",";
  private static final String PRESERVE_DISTCP_OPTION_PREFIX = "-p";

  private String sourcePaths;

  private String targetPath;

  private Map<String, String> distCpArgs;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);

    sourcePaths = args.get(FILE_PATH);
    targetPath = args.get(TARGET_ARG);

    distCpArgs = new HashMap<>(args);
    distCpArgs.remove(FILE_PATH);
    distCpArgs.remove(TARGET_ARG);

    if (!containsPreserveOption(args)) {
      distCpArgs.put(PRESERVE_DISTCP_OPTION_DEFAULT, "");
    }
  }

  @Override
  protected void execute() throws Exception {
    // we need to perform validation and option parsing here
    // because SSM doesn't correctly handle exceptions thrown in the init method
    DistCpOptions distCpOptions = buildDistCpOptions();

    DistCp distCp = new DistCp(getContext().getConf(), distCpOptions);
    appendLog(
        String.format("DistCp Action started at %s for options %s",
            Utils.getFormatedCurrentTime(), distCpOptions));

    try (JobCloseableWrapper jobWrapper = new JobCloseableWrapper(distCp.execute())) {
      distCp.waitForJobCompletion(jobWrapper.job);
      appendLog(jobWrapper.job.getCounters().toString());
    }
  }

  DistCpOptions buildDistCpOptions() {
    validateActionArguments();

    List<String> rawArgs = distCpArgs.entrySet()
        .stream()
        .flatMap(entry -> mapOptionToString(entry.getKey(), entry.getValue()))
        .collect(Collectors.toList());

    if (!distCpArgs.containsKey(SOURCE_PATH_LIST_FILE)) {
      rawArgs.addAll(parseSourcePaths(sourcePaths));
    }
    rawArgs.add(targetPath);

    return OptionsParser.parse(rawArgs.toArray(new String[0]));
  }

  private List<String> parseSourcePaths(String sourcePaths) {
    return Arrays.asList(sourcePaths.split(SOURCE_PATHS_DELIMITER));
  }

  private void validateActionArguments() {
    if (StringUtils.isBlank(sourcePaths) && !distCpArgs.containsKey(SOURCE_PATH_LIST_FILE)) {
      throw new IllegalArgumentException("Source paths not provided, please provide either "
          + FILE_PATH + " either " + SOURCE_PATH_LIST_FILE + " argument");
    }

    if (StringUtils.isNotBlank(sourcePaths) && distCpArgs.containsKey(SOURCE_PATH_LIST_FILE)) {
      throw new IllegalArgumentException(FILE_PATH + " and " + SOURCE_PATH_LIST_FILE
          + " can't be used at the same time. Use only one of the options for specifying source paths.");
    }

    if (StringUtils.isBlank(targetPath)) {
      throw new IllegalArgumentException("Required argument not present: " + TARGET_ARG);
    }
  }

  private Stream<String> mapOptionToString(String key, String value) {
    if (value.isEmpty()) {
      return Stream.of(key);
    }
    return Stream.of(key, value);
  }

  private boolean containsPreserveOption(Map<String, String> args) {
    return args.keySet()
        .stream()
        .anyMatch(option -> option.startsWith(PRESERVE_DISTCP_OPTION_PREFIX));
  }

  /** Used to gracefully close MapReduce job (MR Job is not AutoCloseable inheritor in Hadoop 2.7) */
  private static class JobCloseableWrapper implements AutoCloseable {

    private final Job job;

    private JobCloseableWrapper(Job job) {
      this.job = job;
    }

    @Override
    public void close() throws Exception {
      Cluster cluster = job.getCluster();
      if (cluster != null) {
        cluster.close();
      }
    }
  }
}
