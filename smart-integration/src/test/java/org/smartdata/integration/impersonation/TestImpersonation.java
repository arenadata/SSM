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
package org.smartdata.integration.impersonation;

import io.restassured.response.Response;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.CmdletDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.conf.SmartConf;
import org.smartdata.integration.IntegrationTestBase;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.CmdletsApiWrapper;
import org.smartdata.integration.api.RulesApiWrapper;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;

import static org.smartdata.http.config.ConfigKeys.PREDEFINED_BASIC_AUTH_ENABLED;
import static org.smartdata.http.config.ConfigKeys.PREDEFINED_USERS;
import static org.smartdata.http.config.ConfigKeys.WEB_SECURITY_ENABLED;
import static org.smartdata.integration.auth.AuthUtils.securedApiConfig;

@RunWith(Parameterized.class)
public abstract class TestImpersonation extends IntegrationTestBase {

  @Parameterized.Parameter
  public boolean authenticationEnabled;

  @Parameterized.Parameters(name = "authenticationEnabled = {0}")
  public static Object[] parameters() {
    return new Object[]{true, false};
  }

  @Override
  protected SmartConf withHdfsOptions(SmartConf conf) throws IOException {
    String currentUser = UserGroupInformation.getCurrentUser().getUserName();
    conf.set("hadoop.proxyuser." + currentUser + ".groups", "*");
    conf.set("hadoop.proxyuser." + currentUser + ".hosts", "*");
    return conf;
  }

  @Override
  protected SmartConf withSsmServerOptions(SmartConf conf) {
    setImpersonationOptions(conf);
    if (authenticationEnabled) {
      conf.setBoolean(WEB_SECURITY_ENABLED, true);
      conf.setBoolean(PREDEFINED_BASIC_AUTH_ENABLED, true);
      conf.set(PREDEFINED_USERS, "john:k1tt3n,mary:r0s3,jerry:t0m");
    }

    return conf;
  }

  @Test
  public void testCreateFile() throws IOException {
    createDirectoryWithWriteAccess(new Path("/test"));

    // create different files by different users on single cluster;
    // in case of disabled auth, owners should be the same
    testCreateFile("john", "k1tt3n");
    testCreateFile("mary", "r0s3");
    testCreateFile("jerry", "t0m");
  }

  @Test
  public void testCreateFileByRule() throws IOException {
    createDirectoryWithWriteAccess(new Path("/tmp"));
    createDirectoryWithWriteAccess(new Path("/dest"));

    testCreateFileByRule("john", "k1tt3n");
    testCreateFileByRule("mary", "r0s3");
    testCreateFileByRule("jerry", "t0m");
  }

  protected abstract void setImpersonationOptions(SmartConf conf);

  protected abstract String getProxyUserFor(String username) throws IOException;

  private void testCreateFile(String username, String password) throws IOException {
    String fileToCreate = "/test/file_" + username;

    new ActionsApiWrapper(getConfig(username, password))
        .waitTillActionFinished("write -file " + fileToCreate,
            Duration.ofMillis(100),
            Duration.ofSeconds(2));

    FileStatus fileStatus = cluster.getFileSystem()
        .getFileStatus(new Path(fileToCreate));
    Assert.assertEquals(getProxyUserFor(username), fileStatus.getOwner());
  }

  private void testCreateFileByRule(String username, String password) throws IOException {
    String fileToCreate = "file_" + username;
    createFile(new Path("/tmp", new Path(username, fileToCreate)));

    ApiClient.Config clientConfig = getConfig(username, password);

    RulesApiWrapper rulesApiClient = new RulesApiWrapper(clientConfig);
    RuleDto ruleDto = rulesApiClient.waitTillRuleProducedCmdlets(
        "file: every 100ms | path matches \"/tmp/" + username + "/*\" | sync -dest /dest/",
        Duration.ofMillis(100),
        Duration.ofSeconds(10));

    CmdletsApiWrapper cmdletsApiClient = new CmdletsApiWrapper(clientConfig);
    long cmdletId = getRuleFirstCmdletIdWithRetry(cmdletsApiClient, ruleDto.getId());
    cmdletsApiClient.waitTillCmdletFinished(cmdletId,
        Duration.ofMillis(100),
        Duration.ofSeconds(10));

    rulesApiClient.stopRule(ruleDto.getId());
    rulesApiClient.deleteRule(ruleDto.getId());

    FileStatus fileStatus = cluster.getFileSystem()
        .getFileStatus(new Path("/dest", fileToCreate));
    Assert.assertEquals(getProxyUserFor(username), fileStatus.getOwner());
  }

  private ApiClient.Config getConfig(String username, String password) {
    return authenticationEnabled
        ? securedApiConfig(username, password)
        : ApiClient.Config.apiConfig();
  }

  // we have to use retries because of async rule/cmdlet cache synchronization
  private long getRuleFirstCmdletIdWithRetry(CmdletsApiWrapper apiClient, long ruleId) {
    return retryUntil(
        () -> getRuleFirstCmdletId(apiClient, ruleId),
        Optional::isPresent,
        Duration.ofMillis(100),
        Duration.ofSeconds(5)
    ).orElseThrow(() -> new IllegalStateException("Rule didn't produce any cmdlets"));
  }

  private Optional<Long> getRuleFirstCmdletId(CmdletsApiWrapper apiClient, long ruleId) {
    return apiClient
        .rawClient()
        .getCmdlets()
        .ruleIdsQuery(ruleId)
        .executeAs(Response::andReturn)
        .getItems()
        .stream()
        .map(CmdletDto::getId)
        .findFirst();
  }

  private void createDirectoryWithWriteAccess(Path path) throws IOException {
    FileSystem fileSystem = cluster.getFileSystem();
    fileSystem.mkdirs(path);
    fileSystem.setPermission(path, FsPermission.valueOf("drwxrwxrwx"));
  }
}
