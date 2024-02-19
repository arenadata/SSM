#!/usr/bin/env bash

echo "Get configuration from config."
. config
case=${FILE_SIZE}_${FILE_COUNT}
echo "------------------ Your configuration ------------------"

echo "Test case:"
echo $case
echo ""
echo "Source cluster      is ${SRC_CLUSTER}."
echo "Destination cluster is ${DEST_CLUSTER}."
echo "--------------------------------------------------------"

bin=$(dirname "${BASH_SOURCE-$0}")
bin=$(cd "${bin}">/dev/null; pwd)
log="${LOG_DIR}/${case}_distcp_mupnum${MAPPER_NUM}_${TEST_ROUND}.log"
# remove historical data in log file
printf "" > ${log}

printf "Test case ${case} with ${MAPPER_NUM} mappers:\n" > ${log}

echo "==================== test case: $case, mapper num: ${MAPPER_NUM} ============================"
export start_time=`date +%s`
hadoop distcp -m ${MAPPER_NUM} ${SRC_CLUSTER}/${BASE_DIR} ${DEST_CLUSTER}/${BASE_DIR} > $case-${MAPPER_NUM}map.log 2>&1
export end_time=`date +%s`
printf "$((end_time-start_time))s " >> ${log}

printf "\nTest case ${case} with ${MAPPER_NUM} mapper is finished!\n" >> ${log}

