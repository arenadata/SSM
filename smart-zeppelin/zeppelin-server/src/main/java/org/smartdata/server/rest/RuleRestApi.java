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
package org.smartdata.server.rest;

import java.util.stream.Collectors;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.model.RuleState;
import org.smartdata.server.SmartEngine;
import org.smartdata.server.rest.message.JsonResponse;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;

/**
 * Rules APIs.
 */
@Path("/rules")
@Produces("application/json")
public class RuleRestApi {
  private static final Logger LOGGER = LoggerFactory.getLogger(RuleRestApi.class);
  private final SmartEngine smartEngine;

  public RuleRestApi(SmartEngine smartEngine) {
    this.smartEngine = smartEngine;
  }

  @POST
  @Path("/add")
  public Response addRule(@FormParam("ruleText") String ruleText) {
    try {
      LOGGER.info("Adding rule: " + ruleText);
      long ruleId = smartEngine.getRuleManager().submitRule(ruleText, RuleState.NEW);
      return new JsonResponse<>(Response.Status.CREATED, ruleId).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while adding rule: " + e.getLocalizedMessage());
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @POST
  @Path("/{ruleId}/delete")
  public Response deleteRule(@PathParam("ruleId") long ruleId) {
    try {
      smartEngine.getRuleManager().deleteRule(ruleId, false);
      return new JsonResponse<>(Response.Status.OK).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while deleting rule ", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @POST
  @Path("/{ruleId}/start")
  public Response start(@PathParam("ruleId") long ruleId) {
    LOGGER.info("Start rule{}", ruleId);
    try {
      smartEngine.getRuleManager().activateRule(ruleId);
      return new JsonResponse<>(Response.Status.OK).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while starting rule: " + e.getMessage());
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @POST
  @Path("/{ruleId}/stop")
  public Response stop(@PathParam("ruleId") long ruleId) {
    LOGGER.info("Stop rule{}", ruleId);
    try {
      smartEngine.getRuleManager().disableRule(ruleId, true);
      return new JsonResponse<>(Response.Status.OK).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while stopping rule ", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/{ruleId}/info")
  public Response info(@PathParam("ruleId") long ruleId) {
    try {
      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getRuleManager().getRuleInfo(ruleId)).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while getting rule info", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/{ruleId}/cmdlets/{pageIndex}/{numPerPage}/{orderBy}/{isDesc}")
  public Response cmdlets(@PathParam("ruleId") long ruleId,
      @PathParam("pageIndex") int pageIndex,
      @PathParam("numPerPage") int numPerPage,
      @PathParam("orderBy") String orderBy,
      @PathParam("isDesc") String isDesc) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("ruleId={}, pageIndex={}, numPerPage={}, orderBy={}, " +
              "isDesc={}", ruleId, pageIndex, numPerPage, orderBy, isDesc);
    }
    try {
      List<String> orderByList = Arrays.asList(orderBy.split(","));
      List<Boolean> isDescList = Arrays.stream(isDesc.split(","))
          .map(Boolean::parseBoolean)
          .collect(Collectors.toList());

      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getCmdletManager().listCmdletsInfo(ruleId,
              pageIndex,
              numPerPage, orderByList, isDescList)).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while getting cmdlets", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/{ruleId}/cmdlets")
  public Response cmdlets(@PathParam("ruleId") long ruleId) {
    try {
      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getCmdletManager().listCmdletsInfo(ruleId, null)).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while getting cmdlets", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/list")
  public Response ruleList() {
    try {
      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getRuleManager().listRulesInfo()).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while listing rules", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/list/move")
  public Response ruleMoveList() {
    try {
      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getRuleManager().listRulesMoveInfo()).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while listing Move rules", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }

  @GET
  @Path("/list/sync")
  public Response ruleSyncList() {
    try {
      return new JsonResponse<>(Response.Status.OK,
          smartEngine.getRuleManager().listRulesSyncInfo()).build();
    } catch (Exception e) {
      LOGGER.error("Exception in RuleRestApi while listing Sync rules", e);
      return new JsonResponse<>(Response.Status.INTERNAL_SERVER_ERROR,
          e.getMessage(), ExceptionUtils.getStackTrace(e)).build();
    }
  }
}
