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
package org.smartdata.server.engine.cmdlet.agent;

import akka.actor.ActorNotFound;
import akka.actor.ActorRef;
import akka.actor.ActorSystem;
import akka.actor.Props;
import akka.actor.UntypedActor;
import com.typesafe.config.Config;
import org.junit.After;
import org.junit.Test;
import org.smartdata.conf.SmartConf;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import scala.concurrent.Await;
import scala.concurrent.duration.Duration;
import scala.concurrent.duration.FiniteDuration;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_KEYSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_KEYSTORE_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_KEYSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_KEYSTORE_PASSWORD_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_TRUSTSTORE_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_AGENT_SSL_TRUSTSTORE_PASSWORD_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_ENABLED_TRANSPORTS_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_ENGINE_PROVIDER_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_PEER_SUBJECT_PATTERN_KEY;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_SECURITY_PREFIX;
import static org.smartdata.server.engine.cmdlet.agent.AgentConstants.AKKA_SSL_TRANSPORT;

public class TestAgentSsl {
  private static final String PASSWORD = "password";
  private static final String SERVER_SUBJECT_PATTERN = "CN=ssm-server,OU=SSM,O=Test";
  private static final String AGENT_SUBJECT_PATTERN = "CN=ssm-agent,OU=SSM,O=Test";
  private static final String LOCAL_ADDRESS = "127.0.0.1:0";

  private static final FiniteDuration RESOLVE_TIMEOUT = Duration.create(10, TimeUnit.SECONDS);
  private static final FiniteDuration REJECT_TIMEOUT = Duration.create(3, TimeUnit.SECONDS);

  private final List<ActorSystem> systems = new ArrayList<>();

  @After
  public void shutdown() throws Exception {
    for (ActorSystem system : systems) {
      Await.result(system.terminate(), RESOLVE_TIMEOUT);
    }
  }

  @Test
  public void testConfigNotChangedIfSslDisabled() throws Exception {
    SmartConf conf = new SmartConf();
    Config config = AgentUtils.buildAkkaConfig(conf, LOCAL_ADDRESS, AgentSslConfig.Role.SERVER);

    assertEquals(Collections.singletonList("akka.remote.netty.tcp"),
        config.getStringList(AKKA_ENABLED_TRANSPORTS_KEY));
    assertEquals("akka.tcp://AgentMaster@host:7051/user/master",
        AgentUtils.getMasterActorPaths(new String[] {"host:7051"}, false)[0]);
  }

  @Test
  public void testSslConfig() throws Exception {
    SmartConf conf = sslConf();
    Config config = AgentUtils.buildAkkaConfig(conf, "localhost:7051", AgentSslConfig.Role.SERVER);

    assertEquals(Collections.singletonList(AKKA_SSL_TRANSPORT),
        config.getStringList(AKKA_ENABLED_TRANSPORTS_KEY));
    assertEquals(SmartSslEngineProvider.class.getName(),
        config.getString(AKKA_SSL_ENGINE_PROVIDER_KEY));
    assertTrue(config.getBoolean(AKKA_SSL_SECURITY_PREFIX + "require-mutual-authentication"));
    assertEquals(resource("server.p12"), config.getString(AKKA_SSL_SECURITY_PREFIX + "key-store"));
    // the key password defaults to the key store password
    assertEquals(PASSWORD, config.getString(AKKA_SSL_SECURITY_PREFIX + "key-password"));
    assertEquals("TLSv1.2", config.getString(AKKA_SSL_SECURITY_PREFIX + "protocol"));
    assertFalse(config.getStringList(AKKA_SSL_SECURITY_PREFIX + "enabled-algorithms")
        .contains("TLS_RSA_WITH_AES_128_CBC_SHA"));
    // the server checks certificates of agents
    assertEquals(AGENT_SUBJECT_PATTERN, config.getString(AKKA_SSL_PEER_SUBJECT_PATTERN_KEY));
    assertEquals("localhost", config.getString(AgentConstants.AKKA_REMOTE_SSL_HOST_KEY));
    assertEquals(7051, config.getInt(AgentConstants.AKKA_REMOTE_SSL_PORT_KEY));
    // settings of the TCP transport from agent.conf are inherited by the SSL transport
    assertEquals(config.getString("akka.remote.netty.tcp.connection-timeout"),
        config.getString("akka.remote.netty.ssl.connection-timeout"));

    assertArrayEquals(new String[] {"akka.ssl.tcp://AgentMaster@host:7051/user/master"},
        AgentUtils.getMasterActorPaths(new String[] {"host:7051"}, true));
  }

  @Test
  public void testInvalidSslConfig() {
    SmartConf conf = sslConf();
    conf.unset(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY);
    assertConfigError(conf, AgentSslConfig.Role.AGENT,
        "Required option not provided: " + SMART_AGENT_SSL_AGENT_KEYSTORE_KEY);

    conf = sslConf();
    conf.set(SMART_AGENT_SSL_SERVER_KEYSTORE_PASSWORD_KEY, "wrong");
    assertConfigError(conf, AgentSslConfig.Role.SERVER,
        "Failed to load key store " + resource("server.p12"));

    conf = sslConf();
    conf.unset(SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY);
    assertConfigError(conf, AgentSslConfig.Role.SERVER,
        "Required option not provided: " + SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY);

    conf = sslConf();
    conf.unset(SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY);
    assertConfigError(conf, AgentSslConfig.Role.AGENT,
        "Required option not provided: " + SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY);

    conf = sslConf();
    conf.set(SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY, "CN=(");
    assertConfigError(conf, AgentSslConfig.Role.AGENT,
        "Invalid regular expression in option " + SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY);
  }

  @Test
  public void testAgentConnectsToServer() throws Exception {
    String masterPath = startServer(sslConf());
    ActorSystem agent = startSystem(sslConf(), AgentSslConfig.Role.AGENT);

    assertNotNull(resolve(agent, masterPath, RESOLVE_TIMEOUT));
  }

  @Test
  public void testSubjectCheckDisabled() throws Exception {
    SmartConf serverConf = sslConf();
    serverConf.setBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY, false);
    serverConf.unset(SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY);
    Config config = AgentUtils.buildAkkaConfig(
        serverConf, LOCAL_ADDRESS, AgentSslConfig.Role.SERVER);
    assertFalse(config.hasPath(AKKA_SSL_PEER_SUBJECT_PATTERN_KEY));

    String masterPath = startServer(serverConf);
    // trusted certificate issued for the server is accepted without the subject check
    SmartConf agentConf = sslConf();
    agentConf.setBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY, false);
    agentConf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY, resource("server.p12"));
    ActorSystem agent = startSystem(agentConf, AgentSslConfig.Role.AGENT);

    assertNotNull(resolve(agent, masterPath, RESOLVE_TIMEOUT));
  }

  @Test
  public void testUntrustedCertificateRejectedWithoutSubjectCheck() throws Exception {
    SmartConf conf = sslConf();
    conf.setBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY, false);
    String masterPath = startServer(conf);
    SmartConf agentConf = sslConf();
    agentConf.setBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY, false);
    agentConf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY, resource("untrusted.p12"));
    ActorSystem agent = startSystem(agentConf, AgentSslConfig.Role.AGENT);

    assertRejected(agent, masterPath);
  }

  @Test
  public void testPlaintextClientRejected() throws Exception {
    String masterPath = startServer(sslConf());
    ActorSystem agent = startSystem(new SmartConf(), AgentSslConfig.Role.AGENT);

    String plaintextPath = masterPath.replaceFirst(
        "^" + AgentConstants.AKKA_SSL_PROTOCOL, AgentConstants.AKKA_TCP_PROTOCOL);
    assertRejected(agent, plaintextPath);
  }

  @Test
  public void testUntrustedCertificateRejected() throws Exception {
    String masterPath = startServer(sslConf());
    // self-signed certificate with the agent subject
    SmartConf agentConf = sslConf();
    agentConf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY, resource("untrusted.p12"));
    ActorSystem agent = startSystem(agentConf, AgentSslConfig.Role.AGENT);

    assertRejected(agent, masterPath);
  }

  @Test
  public void testServerRejectsNonAgentCertificate() throws Exception {
    String masterPath = startServer(sslConf());
    // trusted certificate, but issued for the server
    SmartConf agentConf = sslConf();
    agentConf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY, resource("server.p12"));
    ActorSystem agent = startSystem(agentConf, AgentSslConfig.Role.AGENT);

    assertRejected(agent, masterPath);
  }

  @Test
  public void testAgentRejectsNonServerCertificate() throws Exception {
    // trusted certificate, but issued for an agent
    SmartConf serverConf = sslConf();
    serverConf.set(SMART_AGENT_SSL_SERVER_KEYSTORE_KEY, resource("agent.p12"));
    serverConf.set(SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY, ".*");
    String masterPath = startServer(serverConf);
    ActorSystem agent = startSystem(sslConf(), AgentSslConfig.Role.AGENT);

    assertRejected(agent, masterPath);
  }

  private String startServer(SmartConf conf) throws IOException {
    ActorSystem server = startSystem(conf, AgentSslConfig.Role.SERVER);
    ActorRef master = server.actorOf(
        Props.create(NoopActor.class), AgentConstants.MASTER_ACTOR_NAME);
    return AgentUtils.getFullPath(server, master.path());
  }

  private ActorSystem startSystem(SmartConf conf, AgentSslConfig.Role role) throws IOException {
    Config config = AgentUtils.buildAkkaConfig(conf, LOCAL_ADDRESS, role);
    ActorSystem system = ActorSystem.apply(role.name(), config);
    systems.add(system);
    return system;
  }

  private ActorRef resolve(
      ActorSystem system, String path, FiniteDuration timeout) throws Exception {
    return Await.result(system.actorSelection(path).resolveOne(timeout), timeout.mul(2));
  }

  private void assertRejected(ActorSystem system, String path) {
    assertThrows(ActorNotFound.class, () -> resolve(system, path, REJECT_TIMEOUT));
  }

  private void assertConfigError(SmartConf conf, AgentSslConfig.Role role, String message) {
    IOException error = assertThrows(IOException.class,
        () -> AgentUtils.buildAkkaConfig(conf, LOCAL_ADDRESS, role));
    assertTrue(error.getMessage(), error.getMessage().startsWith(message));
  }

  private SmartConf sslConf() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SMART_AGENT_SSL_ENABLED_KEY, true);
    conf.setBoolean(SMART_AGENT_SSL_SUBJECT_CHECK_ENABLED_KEY, true);
    conf.set(SMART_AGENT_SSL_TRUSTSTORE_KEY, resource("truststore.p12"));
    conf.set(SMART_AGENT_SSL_TRUSTSTORE_PASSWORD_KEY, PASSWORD);
    conf.set(SMART_AGENT_SSL_SERVER_KEYSTORE_KEY, resource("server.p12"));
    conf.set(SMART_AGENT_SSL_SERVER_KEYSTORE_PASSWORD_KEY, PASSWORD);
    conf.set(SMART_AGENT_SSL_SERVER_SUBJECT_PATTERN_KEY, SERVER_SUBJECT_PATTERN);
    conf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_KEY, resource("agent.p12"));
    conf.set(SMART_AGENT_SSL_AGENT_KEYSTORE_PASSWORD_KEY, PASSWORD);
    conf.set(SMART_AGENT_SSL_AGENT_SUBJECT_PATTERN_KEY, AGENT_SUBJECT_PATTERN);
    return conf;
  }

  private static String resource(String name) {
    try {
      return new File(TestAgentSsl.class.getResource("/agent-ssl/" + name).toURI())
          .getAbsolutePath();
    } catch (URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  public static class NoopActor extends UntypedActor {
    @Override
    public void onReceive(Object message) {
      unhandled(message);
    }
  }
}
