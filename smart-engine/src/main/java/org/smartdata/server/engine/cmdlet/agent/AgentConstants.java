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

public class AgentConstants {

  public static final String MASTER_ACTOR_SYSTEM_NAME = "AgentMaster";
  public static final String MASTER_ACTOR_NAME = "master";
  public static final String AKKA_REMOTE_HOST_KEY = "akka.remote.netty.tcp.hostname";
  public static final String AKKA_REMOTE_PORT_KEY = "akka.remote.netty.tcp.port";
  public static final String AKKA_REMOTE_SSL_HOST_KEY = "akka.remote.netty.ssl.hostname";
  public static final String AKKA_REMOTE_SSL_PORT_KEY = "akka.remote.netty.ssl.port";
  public static final String AKKA_ENABLED_TRANSPORTS_KEY = "akka.remote.enabled-transports";
  public static final String AKKA_SSL_TRANSPORT = "akka.remote.netty.ssl";
  public static final String AKKA_SSL_ENGINE_PROVIDER_KEY =
      "akka.remote.netty.ssl.ssl-engine-provider";
  public static final String AKKA_SSL_SECURITY_PREFIX = "akka.remote.netty.ssl.security.";
  public static final String AKKA_TCP_PROTOCOL = "akka.tcp";
  public static final String AKKA_SSL_PROTOCOL = "akka.ssl.tcp";
  public static final String AKKA_CONF_FILE = "agent.conf";
}
