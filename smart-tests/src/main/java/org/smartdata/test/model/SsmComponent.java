package org.smartdata.test.model;

import io.arenadata.test.model.Component;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum SsmComponent implements Component {
    HADOOP_NAMENODE("hadoop-namenode", 8020),
    HADOOP_DATANODE("hadoop-datanode", 7051),
    SSM_SERVER("ssm-server", 8081),
    SSM_METASTORE_DB("ssm-metastore-db", 5432),
    KDC_SERVER("kdc-server", 749),
    SAMBA("samba", 389),
    PROMETHEUS("prometheus", 9090);

    private final String name;
    private final int port;

    public static SsmComponent fromName(String name) {
        return SsmComponent.valueOf(name.toUpperCase().replace("-", "_"));
    }
}
