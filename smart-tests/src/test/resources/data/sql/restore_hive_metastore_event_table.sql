CREATE TABLE IF NOT EXISTS hive_metastore_event
(
    id                BIGSERIAL NOT NULL,
    external_id       BIGINT NOT NULL,
    event_time        BIGINT NOT NULL,
    event_type        VARCHAR (255) NOT NULL,
    entity_name       VARCHAR (1024) NOT NULL,
    entity_type       VARCHAR (255) NOT NULL,
    catalog_name      VARCHAR (255) NOT NULL,
    db_name           VARCHAR (255),
    table_name        VARCHAR (255),
    message           TEXT,
    message_format    VARCHAR (255),
    related_resources TEXT,
    PRIMARY KEY ( id )
    );