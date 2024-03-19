#!/usr/bin/env bash
# avoid blocking REST API
unset http_proxy
# for python use
export PYTHONPATH=../integration-test:$PYTHONPATH

echo "Get configuration from config."
. config
case=${FILE_SIZE}_${FILE_COUNT}_async
echo "------------------ Your configuration ------------------"
echo ""
echo "Test case:"
echo $case
echo "Destination cluster is ${DEST_CLUSTER}."
echo "Source cluster      is ${SRC_CLUSTER}."

echo ""
echo "Data generate conf:"
echo "Generate data BASE_DIR     is ${BASE_DIR}."
echo "Generate data SRC_NAMENODE is ${SRC_NAMENODE}."
echo "Generate data FILECOUNT    is ${FILE_COUNT}."
echo "Generate data FILESIZE     is ${FILE_SIZE}."
echo "Generate data PARALLELISM  is ${PARALLELISM}."
echo "Generate data BATCH_SIZE   is ${BATCH_SIZE}."
echo "--------------------------------------------------------"

bin=$(dirname "${BASH_SOURCE-$0}")
bin=$(cd "${bin}">/dev/null; pwd)
log="${LOG_DIR}/${case}_ssm_sync_${TEST_ROUND}.log"
# remove historical data in log file
printf "" > ${log}


echo "Test case ${case}:" >> ${log}

echo "==================== test case: $case ============================"
export PYTHONPATH=${bin}/../integration-test:${PYTHONPATH}
nohup python ../integration-test/pyarrow_create_file.py --host ${SRC_NAMENODE} -d ${BASE_DIR} -n ${FILE_COUNT} -s ${FILE_SIZE} -p ${PARALLELISM} -b ${BATCH_SIZE} >> ${log}  2>&1 & python ${bin}/run_ssm_sync.py ${FILE_SIZE} ${FILE_COUNT} ${log} ${BASE_DIR} ${DEST_CLUSTER} ${SSM_BASE_URL}
printf "\nTest case ${case} is finished!\n" >> ${log}
