#!/usr/bin/env bash
echo "Get configuration from config."
. config
# for python use

echo "------------------ Your configuration ------------------"
echo "Generate data BASE_DIR     is ${BASE_DIR}."
echo "Generate data SRC_NAMENODE is ${SRC_NAMENODE}."
echo "Generate data FILECOUNT    is ${FILE_COUNT}."
echo "Generate data FILESIZE     is ${FILE_SIZE}."
echo "Generate data PARALLELISM  is ${PARALLELISM}."
echo "Generate data BATCH_SIZE   is  ${BATCH_SIZE}."
echo "--------------------------------------------------------"

export PYTHONPATH=../integration-test:$PYTHONPATH
python ../integration-test/pyarrow_create_file.py --host ${SRC_NAMENODE} -d ${BASE_DIR} -n ${FILE_COUNT} -s ${FILE_SIZE} -p ${PARALLELISM} -b ${BATCH_SIZE}
