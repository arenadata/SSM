FROM openjdk:8

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      net-tools curl wget netcat procps gnupg libsnappy-dev && rm -rf /var/lib/apt/lists/*

# Install SSH server
RUN apt-get update \
    && apt-get install -y openssh-server \
    && apt-get install -y nano \
    && ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa \
    && cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys

ARG HADOOP_VERSION
ENV HADOOP_VERSION=${HADOOP_VERSION:-3.3.6}

ENV HADOOP_URL https://archive.apache.org/dist/hadoop/core/hadoop-$HADOOP_VERSION/hadoop-$HADOOP_VERSION.tar.gz

# Download Hadoop
RUN set -x \
    && curl -fSL "$HADOOP_URL" -o /tmp/hadoop.tar.gz \
    && tar -xvf /tmp/hadoop.tar.gz -C /opt/ \
    && rm /tmp/hadoop.tar.gz*

# Configure HDFS
RUN ln -s /opt/hadoop-$HADOOP_VERSION/etc/hadoop /etc/hadoop
RUN mkdir /opt/hadoop-$HADOOP_VERSION/logs
RUN mkdir /hadoop-data

RUN mkdir /opt/ssm
RUN mkdir /opt/ssm/bin
RUN mkdir /opt/ssm/lib
RUN mkdir /opt/ssm/conf

ENV HADOOP_HOME=/opt/hadoop-$HADOOP_VERSION
ENV HADOOP_CONF_DIR=/etc/hadoop
ENV MULTIHOMED_NETWORK=1
ENV USER=root
ENV PATH $HADOOP_HOME/bin/:$PATH

ARG SSM_APP_VERSION
ENV HDFS_PARENT_DATA_DIR=/hadoop/dfs

# Configure namenode
ENV HDFS_CONF_dfs_namenode_name_dir=file://$HDFS_PARENT_DATA_DIR/name
RUN mkdir -p /hadoop/dfs/name

# Configure datanode
ENV HDFS_CONF_dfs_datanode_data_dir=file://$HDFS_PARENT_DATA_DIR/data
RUN mkdir -p $HDFS_PARENT_DATA_DIR/data
RUN mkdir -p $HDFS_PARENT_DATA_DIR/ssd-data
RUN mkdir -p $HDFS_PARENT_DATA_DIR/ram-data
RUN mkdir -p $HDFS_PARENT_DATA_DIR/archive-data

ENV SSM_HOME=/opt/ssm
# Copy custom hadoop config files to $HADOOP_CONF_DIR
COPY ./supports/tools/docker/singlehost/conf/* $HADOOP_CONF_DIR/

# Copy ssm jars to $HADOOP_HOME/share/hadoop/common/lib
COPY ./smart-dist/target/smart-data-${SSM_APP_VERSION}/lib/smart-*.jar $HADOOP_HOME/share/hadoop/common/lib/
COPY ./smart-dist/target/smart-data-${SSM_APP_VERSION}/lib/*.jar $SSM_HOME/lib/
COPY ./smart-dist/target/smart-data-${SSM_APP_VERSION}/bin/* $SSM_HOME/bin/
COPY ./supports/tools/docker/singlehost/conf/* $SSM_HOME/conf/

ADD ./supports/tools/docker/singlehost/healthcheck_hadoop.sh /healthcheck_hadoop.sh
RUN chmod a+x /healthcheck_hadoop.sh
ADD ./supports/tools/docker/singlehost/start_hadoop.sh /start_hadoop.sh
RUN chmod a+x /start_hadoop.sh
RUN chmod a+x $SSM_HOME/bin/install.sh
RUN chmod a+x $SSM_HOME/bin/start-ssm.sh

ENTRYPOINT ["/start_hadoop.sh"]