CREATE OR REPLACE FUNCTION create_file_access_partition(input_date timestamp)
    RETURNS INTEGER AS '
    DECLARE
        current_date_part DATE;
        current_date_part_text TEXT;
        partition_table_name TEXT;
        first_day_of_month DATE;
        last_day_of_month DATE;
        result INTEGER;
        create_query TEXT;
    BEGIN
        result := 0;
        current_date_part := CAST(DATE_TRUNC(''month'', input_date::date) AS DATE);
        current_date_part_text := REGEXP_REPLACE(current_date_part::TEXT, ''-'',''_'',''g'');
        partition_table_name := FORMAT(''file_access_%s'', current_date_part_text::TEXT);
        IF (TO_REGCLASS(partition_table_name::TEXT) ISNULL) THEN
            first_day_of_month := current_date_part;
            last_day_of_month := current_date_part + ''1 month''::INTERVAL;
            result := 1;
            RAISE NOTICE ''table: %'', partition_table_name;
            create_query := FORMAT(
                    ''CREATE TABLE %I PARTITION OF file_access FOR VALUES FROM (extract(epoch from %L::DATE) * 1000) TO (extract(epoch from %L::DATE) * 1000);'',
                    partition_table_name, first_day_of_month, last_day_of_month);
            RAISE NOTICE ''query: %'', create_query;
            EXECUTE create_query;
            EXECUTE FORMAT(''CREATE INDEX %1$s__access_time ON %1$I (access_time);'', partition_table_name);
        END IF;
        RETURN result;
    END;
' LANGUAGE plpgsql;
