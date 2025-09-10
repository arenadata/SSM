#!/bin/bash

set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-EOSQL
    CREATE DATABASE hive;
    CREATE DATABASE ssm;

    CREATE USER hive WITH PASSWORD 'hive';
    GRANT ALL PRIVILEGES ON DATABASE hive TO hive;
    GRANT ALL PRIVILEGES ON DATABASE ssm TO ssm;
EOSQL
