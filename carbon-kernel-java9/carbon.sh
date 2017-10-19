#!/bin/sh

DEBUG=''
if [ $1 = 'debug' ]
then
    DEBUG='-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005'
fi

java \
 $DEBUG \
 -Dlog4j.configurationFile=log4j2.xml \
 -Dcarbon.home=/home/jayanga/WSO2/WSO2SourceCode/git/java9/carbon-kernel/carbon-kernel-java9 \
 -Dwso2.runtime.path=/home/jayanga/WSO2/WSO2SourceCode/git/java9/carbon-kernel/carbon-kernel-java9 \
 --module-path /home/jayanga/WSO2/WSO2SourceCode/git/java9/carbon-kernel/carbon-kernel-java9 \
 --add-modules java.se.ee,java.xml.bind \
 -m org.wso2.carbon.launcher/org.wso2.carbon.launcher.Main
## -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005 \
## -m org.wso2.carbon.launcher/org.wso2.carbon.launcher.Main
