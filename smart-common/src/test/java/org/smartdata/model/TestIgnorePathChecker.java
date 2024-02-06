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

package org.smartdata.model;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.smartdata.conf.SmartConf;

import static org.smartdata.conf.SmartConfKeys.SMART_IGNORED_PATH_TEMPLATES_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_IGNORE_DIRS_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_INTERNAL_PATH_TEMPLATES_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_INTERNAL_PATH_TEMPLATES_KEY;
import static org.smartdata.model.TestIgnorePathChecker.Parameters.ignoreDirs;
import static org.smartdata.model.TestIgnorePathChecker.Parameters.internalTemplates;
import static org.smartdata.model.TestIgnorePathChecker.Parameters.templates;

@RunWith(Parameterized.class)
public class TestIgnorePathChecker {

  @Parameterized.Parameter(0)
  public String ignoreTemplates;

  @Parameterized.Parameter(1)
  public String ignoreDirs;

  @Parameterized.Parameter(2)
  public String pathToCheck;

  @Parameterized.Parameter(3)
  public boolean shouldIgnorePath;

  @Parameterized.Parameter(4)
  public String internalTemplates;

  @Parameterized.Parameters(
      name = "ignoreTemplates = {0}, ignoreDirs = {1}, pathToCheck = {2}, internalTemplates = {4}")
  public static Object[] parameters() {
    return new Object[][] {
        // check templates from smart.ignore.path.templates
        templates(".*test_file\\..*").shouldMatch("/path/files/test_file.txt"),
        templates(".*test_file\\.txt").shouldMatch("/path/files/test_file.txt"),
        templates("/path/files/.*").shouldMatch("/path/files/test_file.txt"),
        templates(".*/files/.*").shouldMatch("/path/files/test_file.txt"),
        templates("/path.*").shouldMatch("/path/files/test_file.txt"),
        templates("/path/files/.*", "/path/another_dir/").shouldMatch("/path/files/test_file.txt"),
        templates("/path/.*", ".*test_file\\..*").shouldMatch("/path/files/test_file.txt"),
        templates("/path/files/.*").shouldNotMatch("/another_dir/test_file.txt"),

        // check templates from smart.ignore.dirs
        ignoreDirs("/path/files").shouldMatch("/path/files/test_file.txt"),
        ignoreDirs("/path/files/").shouldMatch("/path/files/test_file.txt"),
        ignoreDirs("/path/").shouldMatch("/path/files/test_file.txt"),
        templates("/path/.*").withIgnoreDirs("/path/").shouldMatch("/path/files/test_file.txt"),

        // check templates from smart.internal.path.templates
        templates().shouldMatch("/.ignored"),
        templates().shouldMatch("/another_dir/.ignored"),
        templates().shouldMatch("/another_dir/.ignored_dir/file"),
        templates("/test/.*").shouldMatch("/__ignored"),
        templates().shouldMatch("/dir/__ignored"),
        templates(".*/root.*").shouldMatch("/dir/__tmp_dir/txt"),
        templates().shouldMatch("/test/copy_file.bin._COPYING_"),
        templates().shouldNotMatch("/dir/not_temporary.file"),

        internalTemplates(".*_DELETING_.*").shouldMatch("/test/copy_file.bin._DELETING_"),
        internalTemplates(".*_DELETING_.*").shouldNotMatch("/copy_file.bin._COPYING_"),
    };
  }

  @Test
  public void testShouldIgnorePath() {
    SmartConf configuration = new SmartConf();
    configuration.set(SMART_IGNORED_PATH_TEMPLATES_KEY, ignoreTemplates);
    configuration.set(SMART_IGNORE_DIRS_KEY, ignoreDirs);
    configuration.set(SMART_INTERNAL_PATH_TEMPLATES_KEY, internalTemplates);
    PathChecker pathChecker = new PathChecker(configuration);

    Assert.assertEquals(shouldIgnorePath, pathChecker.isIgnored(pathToCheck));
  }

  static class Parameters {
    private String ignoreTemplates = "";
    private String ignoreDirs = "";
    private String pathToCheck;
    private boolean shouldIgnorePath;

    private String internalTemplates = SMART_INTERNAL_PATH_TEMPLATES_DEFAULT;

    public static Parameters templates(String... templates) {
      Parameters args = new Parameters();
      args.ignoreTemplates = String.join(",", templates);
      return args;
    }

    public static Parameters internalTemplates(String... templates) {
      Parameters args = new Parameters();
      args.internalTemplates = String.join(",", templates);
      return args;
    }

    public static Parameters ignoreDirs(String... dirs) {
      return new Parameters().withIgnoreDirs(dirs);
    }

    public Parameters withIgnoreDirs(String... dirs) {
      this.ignoreDirs = String.join(",", dirs);
      return this;
    }

    public Object[] shouldMatch(String pathToCheck) {
      this.pathToCheck = pathToCheck;
      this.shouldIgnorePath = true;
      return asJunitParameters();
    }

    public Object[] shouldNotMatch(String pathToCheck) {
      this.pathToCheck = pathToCheck;
      this.shouldIgnorePath = false;
      return asJunitParameters();
    }

    private Object[] asJunitParameters() {
      return new Object[] {ignoreTemplates, ignoreDirs,
          pathToCheck, shouldIgnorePath, internalTemplates};
    }
  }
}
