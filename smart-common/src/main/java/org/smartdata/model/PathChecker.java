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
package org.smartdata.model;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.smartdata.SmartConstants;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.utils.ConfigUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.smartdata.conf.SmartConfKeys.SMART_IGNORED_PATH_TEMPLATES_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_IGNORE_DIRS_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_INTERNAL_PATH_TEMPLATES_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_INTERNAL_PATH_TEMPLATES_KEY;

public class PathChecker {
  private static final String IGNORED_PATH_TEMPLATES_DELIMITER = ",";

  private final ThreadLocal<Matcher> patternMatcherThreadLocal;
  private final List<String> coverDirs;

  public PathChecker(Configuration configuration) {
    this(getIgnorePatterns(configuration), ConfigUtil.getCoverDirs(configuration));
  }

  public PathChecker(List<String> ignoredPathPatterns, List<String> coverDirs) {
    StringJoiner patternBuilder = new StringJoiner("|", "(", ")");
    ignoredPathPatterns.forEach(patternBuilder::add);

    Pattern pattern = Pattern.compile(patternBuilder.toString());
    this.patternMatcherThreadLocal =
        ThreadLocal.withInitial(() -> pattern.matcher(""));
    this.coverDirs = coverDirs;
  }

  public boolean isIgnored(String absolutePath) {
    return patternMatcherThreadLocal.get()
        .reset(absolutePath)
        .find();
  }

  public boolean isCovered(String absolutePath) {
    return coverDirs.isEmpty()
        || coverDirs.stream().anyMatch(absolutePath::startsWith);
  }

  public List<String> getCoverDirs() {
    return coverDirs;
  }

  private static List<String> getIgnorePatterns(Configuration configuration) {
    // add ignored path templates
    Set<String> ignoredPathTemplates = new HashSet<>(
        parseIgnoredPathOptions(configuration, SMART_IGNORED_PATH_TEMPLATES_KEY)
    );

    // add system directory
    ignoredPathTemplates.add(dirToPathTemplate(SmartConstants.SYSTEM_FOLDER));

    // add legacy ignored dirs
    parseIgnoredPathOptions(configuration, SMART_IGNORE_DIRS_KEY)
        .stream()
        .map(PathChecker::dirToPathTemplate)
        .forEach(ignoredPathTemplates::add);

    // add all files under SSM working dir
    String ssmWorkDir = configuration.get(
        SmartConfKeys.SMART_WORK_DIR_KEY, SmartConfKeys.SMART_WORK_DIR_DEFAULT);
    ignoredPathTemplates.add(dirToPathTemplate(ssmWorkDir));

    // add internal file templates
    List<String> internalFileTemplates = parseIgnoredPathOptions(configuration,
        SMART_INTERNAL_PATH_TEMPLATES_KEY, SMART_INTERNAL_PATH_TEMPLATES_DEFAULT);
    ignoredPathTemplates.addAll(internalFileTemplates);

    return new ArrayList<>(ignoredPathTemplates);
  }

  private static List<String> parseIgnoredPathOptions(
      Configuration configuration, String optionKey) {
    return parseIgnoredPathOptions(configuration, optionKey, null);
  }

  private static List<String> parseIgnoredPathOptions(
      Configuration configuration,
      String optionKey,
      String defaultValue
  ) {
    String rawIgnorePaths = configuration.get(optionKey, defaultValue);
    return StringUtils.isNotBlank(rawIgnorePaths)
        ? Arrays.asList(rawIgnorePaths.split(IGNORED_PATH_TEMPLATES_DELIMITER))
        : Collections.emptyList();
  }

  private static String dirToPathTemplate(String dirPath) {
    String postfix = dirPath.endsWith("/") ? ".*" : "/.*";
    return dirPath + postfix;
  }
}
