#!/usr/bin/env bash
# avoid blocking REST API
unset http_proxy
# for python use
export PYTHONPATH=../integration-test:$PYTHONPATH

echo "Get configuration from config."
. config
case=${FILE_SIZE}_${FILE_COUNT}
echo "------------------ Your configuration ------------------"
echo "Test case:"
echo $case
echo ""
echo "Destination cluster is ${DEST_CLUSTER}."
echo "Source cluster      is ${SRC_CLUSTER}."
echo "--------------------------------------------------------"

bin=$(dirname "${BASH_SOURCE-$0}")
bin=$(cd "${bin}">/dev/null; pwd)
log="${LOG_DIR}/${case}_ssm_sync_${TEST_ROUND}.log"
# remove historical data in log file
printf "" > ${log}


echo "Test case ${case}:" >> ${log}

echo "==================== test case: $case ============================"
# make ssm log empty before test
export PYTHONPATH=${bin}/../integration-test:${PYTHONPATH}
python ${bin}/run_ssm_sync.py ${FILE_SIZE} ${FILE_COUNT} ${log} ${BASE_DIR} ${DEST_CLUSTER} ${SSM_BASE_URL}

printf "\nTest case ${case} is finished!\n" >> ${log}
