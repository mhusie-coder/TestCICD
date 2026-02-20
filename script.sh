#!/usr/bin/env bash
for parent in $(ls './deployed'); do
    for child in $(ls ./deployed/$parent); do
        cd ./current/$parent/$child/
        echo "<project xmlns='http://maven.apache.org/POM/4.0.0'
	xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
	xsi:schemaLocation='http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd'>
	<parent>
		<artifactId>parent-pom</artifactId>
		<groupId>apigee</groupId>
		<version>1.0</version>
		<relativePath>./deploy-sharedflows-proxies/samples/mockapi-recommended/gateway/shared-pom.xml</relativePath>
	</parent>

	<modelVersion>4.0.0</modelVersion>
	<groupId>apigee</groupId>
	<artifactId>$child</artifactId>
	<version>1.0</version>
	<name>$child</name>
	<packaging>pom</packaging>
</project>" > ./pom.xml
	mvn clean install -Ptest -D'bearer'=$GITHUB_OUTPUT
    cd ../../..
    done
done