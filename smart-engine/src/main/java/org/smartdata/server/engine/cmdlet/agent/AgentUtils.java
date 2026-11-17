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

import akka.actor.ActorPath;
import akka.actor.ActorRef;
import akka.actor.ActorSystem;
import akka.actor.Address;
import akka.actor.Cancellable;
import akka.actor.ExtendedActorSystem;
import akka.actor.Scheduler;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigValue;
import com.typesafe.config.ConfigValueFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import scala.concurrent.ExecutionContextExecutor;
import scala.concurrent.duration.FiniteDuration;

public class AgentUtils {

  public static Address getSystemAddres(ActorSystem system) {
    return ((ExtendedActorSystem) system).provider().getDefaultAddress();
  }

  public static String getFullPath(ActorSystem system, ActorPath path) {
    return path.toStringWithAddress(getSystemAddres(system));
  }

  public static String getHostPort(ActorRef ref) {
    return ref.path().address().hostPort().replaceFirst("^.*@", "");
  }

  public static Cancellable repeatActionUntil(ActorSystem system,
      FiniteDuration initialDelay, FiniteDuration interval, FiniteDuration timeout,
      Runnable action, Runnable onTimeout) {
    final Scheduler scheduler = system.scheduler();
    final ExecutionContextExecutor dispatcher = system.dispatcher();
    final AtomicBoolean cancelled = new AtomicBoolean(false);
    final Cancellable run =
        scheduler.schedule(initialDelay, interval, action,
            dispatcher);
    final Cancellable cancelRun = scheduler.scheduleOnce(timeout, new Runnable() {
      @Override
      public void run() {
        run.cancel();
      }
    }, dispatcher);
    final Cancellable fail = scheduler.scheduleOnce(timeout, new Runnable() {
      @Override
      public void run() {
        if (!cancelled.get()) {
          onTimeout.run();
        }
      }
    }, dispatcher);

    return new Cancellable() {

      @Override
      public boolean cancel() {
        cancelled.set(true);
        boolean runCancelled = run.cancel();
        boolean cancelRunCancelled = cancelRun.cancel();
        boolean failCancelled = fail.cancel();
        return runCancelled && cancelRunCancelled && failCancelled;
      }

      @Override
      public boolean isCancelled() {
        return cancelled.get() && run.isCancelled() && cancelRun.isCancelled()
            && fail.isCancelled();
      }
    };
  }

  public static String[] getMasterActorPaths(String[] masters, boolean sslEnabled) {
    String[] paths = new String[masters.length];
    for (int i = 0; i < masters.length; i++) {
      paths[i] = getMasterActorPath(masters[i], sslEnabled);
    }
    return paths;
  }

  private static String getMasterActorPath(String masterAddress, boolean sslEnabled) {
    HostPort hostPort = new HostPort(masterAddress);
    return String.format("%s://%s@%s:%s/user/%s",
        sslEnabled ? AgentConstants.AKKA_SSL_PROTOCOL : AgentConstants.AKKA_TCP_PROTOCOL,
        AgentConstants.MASTER_ACTOR_SYSTEM_NAME,
        hostPort.getHost(), hostPort.getPort(),
        AgentConstants.MASTER_ACTOR_NAME);
  }

  /**
   * Build the Akka config of the Server-Agent communication bound to the given address.
   */
  public static Config buildAkkaConfig(
      SmartConf conf, String address, AgentSslConfig.Role role) throws IOException {
    Config config = overrideRemoteAddress(
        ConfigFactory.load(AgentConstants.AKKA_CONF_FILE), address);
    return AgentSslConfig.apply(config, conf, role);
  }

  public static Config overrideRemoteAddress(Config config, String address) {
    AgentUtils.HostPort hostPort = new AgentUtils.HostPort(address);
    ConfigValue host = ConfigValueFactory.fromAnyRef(hostPort.getHost());
    ConfigValue port = ConfigValueFactory.fromAnyRef(hostPort.getPort());
    // the config is already resolved, so the SSL transport doesn't inherit
    // these values from the TCP transport and has to be overridden separately
    return config.withValue(AgentConstants.AKKA_REMOTE_HOST_KEY, host)
        .withValue(AgentConstants.AKKA_REMOTE_PORT_KEY, port)
        .withValue(AgentConstants.AKKA_REMOTE_SSL_HOST_KEY, host)
        .withValue(AgentConstants.AKKA_REMOTE_SSL_PORT_KEY, port);
  }

  /**
   * Return master address list.
   *
   * @param conf
   * @return address array if valid address found, else null
   */
  public static String[] getMasterAddress(SmartConf conf) {
    String[] masters = conf.getStrings(SmartConfKeys.SMART_AGENT_MASTER_ADDRESS_KEY);
    int masterDefPort = conf.getInt(SmartConfKeys.SMART_AGENT_MASTER_PORT_KEY,
        SmartConfKeys.SMART_AGENT_MASTER_PORT_DEFAULT);

    if (masters == null || masters.length == 0) {
      return null;
    }

    for (int i = 0; i < masters.length; i++) {
      if (!masters[i].contains(":")) {
        masters[i] += ":" + masterDefPort;
      }
    }
    return masters;
  }

  /**
   * Return agent address.
   *
   * @param conf
   * @return
   * @throws IOException
   */
  public static String getAgentAddress(SmartConf conf) throws IOException {
    String agentAddress = conf.get(SmartConfKeys.SMART_AGENT_ADDRESS_KEY);
    if (agentAddress == null) {
      agentAddress = InetAddress.getLocalHost().getHostName();
    }
    int agentDefPort =
        conf.getInt(SmartConfKeys.SMART_AGENT_PORT_KEY, SmartConfKeys.SMART_AGENT_PORT_DEFAULT);
    if (!agentAddress.contains(":")) {
      agentAddress += ":" + agentDefPort;
    }
    return agentAddress;
  }

  public static class HostPort {

    private final String host;
    private final String port;

    public HostPort(String address) {
      String[] hostPort = address.split(":");
      host = hostPort[0];
      port = hostPort[1];
    }

    public String getHost() {
      return host;
    }

    public String getPort() {
      return port;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      HostPort hostPort = (HostPort) o;
      return Objects.equals(host, hostPort.host) && Objects.equals(port, hostPort.port);
    }

    @Override
    public int hashCode() {
      return Objects.hash(host, port);
    }

    @Override
    public String toString() {
      return "HostPort{ host='" + host + '\'' + ", port='" + port + '\'' + '}';
    }
  }
}
