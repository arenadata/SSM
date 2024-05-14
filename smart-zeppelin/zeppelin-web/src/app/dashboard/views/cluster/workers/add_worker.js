/*
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
angular.module('zeppelinWebApp')

  .controller('AddWorkerCtrl', ['$scope', 'restapi', 'i18n',
    function ($scope, restapi, i18n) {
      'use strict';

      $scope.description = i18n.terminology.worker;
      $scope.count = 1;

      $scope.add = function () {
        $scope.adding = true;
        $scope.shouldNoticeSubmitFailed = false;
        return restapi.addWorker(
          function handleResponse(response) {
            $scope.shouldNoticeSubmitFailed = !response.success;
            $scope.adding = false;
            if (response.success) {
              $scope.$hide();
            } else {
              $scope.error = response.error;
            }
          },
          function handleException(ex) {
            $scope.shouldNoticeSubmitFailed = true;
            $scope.adding = false;
            $scope.error = ex;
          }
        );
      };
    }])
;
