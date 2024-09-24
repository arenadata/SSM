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
package org.smartdata.http.error;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.SsmParseException;
import org.smartdata.exception.StateTransitionException;
import org.smartdata.metastore.MetaStoreException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.validation.ConstraintViolationException;

import java.io.IOException;
import java.util.stream.Collectors;

@ControllerAdvice
public class SmartExceptionHandler extends ResponseEntityExceptionHandler {
  private static final Logger LOG = LoggerFactory.getLogger(SmartExceptionHandler.class);

  @ExceptionHandler(value = {
      MetaStoreException.class,
      MetaDataAccessException.class,
      DataAccessException.class
  })
  protected ResponseEntity<Object> handleDbExceptions(
      Exception exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        request,
        SsmErrorCode.DB_ERROR,
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(value = IOException.class)
  protected ResponseEntity<Object> handleSsmExceptions(
      Exception exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        request,
        SsmErrorCode.SSM_INTERNAL_ERROR,
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(value = SsmParseException.class)
  protected ResponseEntity<Object> handleParseExceptions(
      SsmParseException exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        request,
        SsmErrorCode.PARSE_ERROR,
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(StateTransitionException.class)
  protected ResponseEntity<Object> handleStateTransitionException(
      Exception exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        request,
        SsmErrorCode.STATE_TRANSITION_ERROR,
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(value = {
      ConstraintViolationException.class,
      IllegalArgumentException.class
  })
  protected ResponseEntity<Object> handleValidationExceptions(
      Exception exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        request,
        SsmErrorCode.VALIDATION_ERROR,
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(value = {NotFoundException.class})
  protected ResponseEntity<Object> handleNotFoundException(
      Exception exception, WebRequest request) {
    return handleExceptionInternal(
        exception,
        null,
        new HttpHeaders(),
        HttpStatus.NOT_FOUND,
        request);
  }

  @Override
  protected ResponseEntity<Object> handleMethodArgumentNotValid(
      MethodArgumentNotValidException exception,
      HttpHeaders headers,
      HttpStatus status,
      WebRequest request) {
    return handleValidationExceptions(exception, request);
  }

  @Override
  protected ResponseEntity<Object> handleTypeMismatch(
      TypeMismatchException exception,
      HttpHeaders headers,
      HttpStatus status,
      WebRequest request) {
    return handleValidationExceptions(exception, request);
  }

  @Override
  protected ResponseEntity<Object> handleBindException(
      BindException exception,
      HttpHeaders headers,
      HttpStatus status,
      WebRequest request) {
      String errorMessage = exception.getBindingResult().getAllErrors().stream()
              .map(DefaultMessageSourceResolvable::getDefaultMessage)
              .collect(Collectors.joining(";"));
      return handleExceptionInternal(
            exception,
            request,
            HttpStatus.BAD_REQUEST,
            new ErrorDto<>(
                    SsmErrorCode.VALIDATION_ERROR.getCode(),
                    errorMessage,
                    ExceptionUtils.getStackTrace(exception))
            );
  }

  private ResponseEntity<Object> handleExceptionInternal(
      Exception exception, WebRequest request, SsmErrorCode errorCode, HttpStatus status) {
    ErrorDto<String> errorBody = new ErrorDto<>(
        errorCode.getCode(),
        exception.getMessage(),
        ExceptionUtils.getStackTrace(exception));

    return handleExceptionInternal(exception,
            request,
            status,
            errorBody);
  }

  private ResponseEntity<Object> handleExceptionInternal(
          Exception exception, WebRequest request, HttpStatus status, ErrorDto<String> errorBody) {
    LOG.error("Exception during handling request on {}",
            request.getDescription(false), exception);

    return handleExceptionInternal(
            exception,
            errorBody,
            new HttpHeaders(),
            status,
            request);
  }
}
