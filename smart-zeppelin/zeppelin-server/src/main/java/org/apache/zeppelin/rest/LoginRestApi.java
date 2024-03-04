/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.rest;

import java.util.Collection;
import java.util.Iterator;
import javax.ws.rs.GET;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response.Status;
import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.notebook.NotebookAuthorization;
import org.apache.zeppelin.realm.kerberos.KerberosRealm;
import org.apache.zeppelin.realm.kerberos.KerberosToken;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.server.SmartZeppelinServer;
import org.apache.zeppelin.ticket.TicketContainer;
import org.apache.zeppelin.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.UserInfo;
import org.smartdata.server.SmartEngine;
import org.smartdata.utils.StringUtil;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Created for org.apache.zeppelin.rest.message on 17/03/16.
 */

@Path("/login")
@Produces("application/json")
public class LoginRestApi {
  private SmartEngine engine = new SmartZeppelinServer().getEngine();
  private static final Logger LOG = LoggerFactory.getLogger(LoginRestApi.class);
  public static final String SSM_ADMIN = "admin";

  /**
   * Required by Swagger.
   */
  public LoginRestApi() {
    super();
  }

  private JsonResponse proceedToLogin(Subject currentUser, AuthenticationToken token) {
    JsonResponse response = null;
    try {
      currentUser.getSession().stop();
      currentUser.getSession(true);
      // Login will fail if username/password doesn't match with the one
      // configured in conf/shiro.ini.
      currentUser.login(token);

      HashSet<String> roles = SecurityUtils.getRoles();
      String principal = SecurityUtils.getPrincipal();
      String ticket;
      if ("anonymous".equals(principal))
        ticket = "anonymous";
      else
        ticket = TicketContainer.instance.getTicket(principal);

      Map<String, String> data = new HashMap<>();
      data.put("principal", principal);
      data.put("roles", roles.toString());
      data.put("ticket", ticket);

      response = new JsonResponse(Response.Status.OK, "", data);
      //if no exception, that's it, we're done!

      //set roles for user in NotebookAuthorization module
      NotebookAuthorization.getInstance().setRoles(principal, roles);
    } catch (UnknownAccountException uae) {
      //username wasn't in the system, show them an error message?
      LOG.error("Exception in login: ", uae);
    } catch (IncorrectCredentialsException ice) {
      //password didn't match, try again?
      LOG.error("Exception in login: ", ice);
    } catch (LockedAccountException lae) {
      //account for that username is locked - can't login.  Show them a message?
      LOG.error("Exception in login: ", lae);
    } catch (AuthenticationException ae) {
      //unexpected condition - error?
      LOG.error("Exception in login: ", ae);
    }
    return response;
  }

  /**
   * Post Login
   * Returns userName & password
   * for anonymous access, username is always anonymous.
   * After getting this ticket, access through websockets become safe
   *
   * @return 200 response
   */
  @POST
  @ZeppelinApi
  public Response postLogin(@FormParam("userName") String userName,
      @FormParam("password") String password) {
    LOG.debug("userName: {}", userName);
    // ticket set to anonymous for anonymous user. Simplify testing.
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    if (currentUser.isAuthenticated()) {
      currentUser.logout();
    }
    LOG.debug("currentUser: {}", currentUser);
    JsonResponse<Map<String, String>> response = null;
    if (!currentUser.isAuthenticated()) {

      UsernamePasswordToken token = new UsernamePasswordToken(userName, password);

      response = proceedToLogin(currentUser, token);
    }

    if (response == null) {
      response = new JsonResponse<>(Response.Status.FORBIDDEN, "", null);
    }

    LOG.info(response.toString());
    return response.build();
  }

  @GET
  @ZeppelinApi
  public Response getLogin(@Context HttpHeaders headers) {
    JsonResponse response = null;
    KerberosRealm kerberosRealm = getKerberosRealm();
    if (null != kerberosRealm) {
      try {
        Map<String, Cookie> cookies = headers.getCookies();
        KerberosToken kerberosToken = KerberosRealm.getKerberosTokenFromCookies(cookies);
        if (null != kerberosToken) {
          Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
          String name = (String) kerberosToken.getPrincipal();
          if (!currentUser.isAuthenticated() || !currentUser.getPrincipal().equals(name)) {
            response = proceedToLogin(currentUser, kerberosToken);
          }
        }
        if (null == response) {
          LOG.warn("No Kerberos token received");
          response = new JsonResponse<>(Status.UNAUTHORIZED, "", null);
        }
        return response.build();
      } catch (AuthenticationException e){
        LOG.error("Error in Login", e);
      }
    }
    return new JsonResponse<>(Status.BAD_REQUEST).build();
  }

  private KerberosRealm getKerberosRealm() {
    Collection realmsList = SecurityUtils.getRealmsList();
    if (realmsList != null) {
      for (Iterator<Realm> iterator = realmsList.iterator(); iterator.hasNext(); ) {
        Realm realm = iterator.next();
        String name = realm.getClass().getName();

        LOG.debug("RealmClass.getName: " + name);

        if (name.equals("org.apache.zeppelin.realm.kerberos.KerberosRealm")) {
          return (KerberosRealm) realm;
        }
      }
    }
    return null;
  }

  @POST
  @Path("logout")
  @ZeppelinApi
  public Response logout() {
    JsonResponse response;
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    currentUser.logout();
    response = new JsonResponse(Response.Status.UNAUTHORIZED, "", "");
    return response.build();
  }
}
