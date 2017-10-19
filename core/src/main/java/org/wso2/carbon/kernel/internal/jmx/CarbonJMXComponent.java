/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.carbon.kernel.internal.jmx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.CarbonRuntime;
import org.wso2.carbon.kernel.config.model.CarbonConfiguration;
import org.wso2.carbon.kernel.internal.config.JMXConfiguration;
import org.wso2.carbon.kernel.jmx.connection.SingleAddressRMIServerSocketFactory;
import org.wso2.carbon.kernel.jmx.security.CarbonJMXAuthenticator;

import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

/**
 * This service component is responsible for initializing and starting the JMXConnectorServer which enables remote
 * JMX monitors to connect to the Platform JMX Server.
 *
 * @since 5.1.0
 */
public class CarbonJMXComponent {
    private static final Logger logger = LoggerFactory.getLogger(CarbonJMXComponent.class);
    private static final String JAVA_RMI_SERVER_HOSTNAME = "java.rmi.server.hostname";
    private JMXConnectorServer jmxConnectorServer;
    private Registry rmiRegistry;
    private CarbonRuntime carbonRuntime;

    public CarbonJMXComponent(CarbonRuntime carbonRuntime) {
        this.carbonRuntime = carbonRuntime;
    }

    public void start() throws Exception {
        try {
            CarbonConfiguration carbonConfiguration = carbonRuntime.getConfiguration();
            JMXConfiguration jmxConfiguration = carbonConfiguration.getJmxConfiguration();
            if (!jmxConfiguration.isEnabled()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Remote JMX is disabled.");
                }
                return;
            }

            String hostname = System.getProperty(JAVA_RMI_SERVER_HOSTNAME);
            if (hostname == null || hostname.isEmpty()) {
                hostname = jmxConfiguration.getHostName();
                System.setProperty(JAVA_RMI_SERVER_HOSTNAME, hostname);
            }

            InetAddress[] inetAddresses = InetAddress.getAllByName(hostname);
            if (inetAddresses.length == 0) {
                if (logger.isDebugEnabled()) {
                    logger.debug("No network interface available for '{}' to start JMXConnectorServer", hostname);
                }
                return;
            }

            SingleAddressRMIServerSocketFactory singleAddressRMIServerSocketFactory =
                    new SingleAddressRMIServerSocketFactory(inetAddresses[0]);
            rmiRegistry = LocateRegistry.createRegistry(jmxConfiguration.getRmiRegistryPort(), null,
                    singleAddressRMIServerSocketFactory);

            String jmxURL = "service:jmx:rmi://" + hostname + ":" + jmxConfiguration.getRmiServerPort()
                    + "/jndi/rmi://" + hostname + ":" + jmxConfiguration.getRmiRegistryPort() + "/jmxrmi";
            JMXServiceURL jmxServiceURL = new JMXServiceURL(jmxURL);

            HashMap<String, Object> environment = new HashMap<>();
            environment.put(JMXConnectorServer.AUTHENTICATOR, new CarbonJMXAuthenticator());
            environment.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE,
                    singleAddressRMIServerSocketFactory);

            jmxConnectorServer = JMXConnectorServerFactory.newJMXConnectorServer(jmxServiceURL, environment,
                    ManagementFactory.getPlatformMBeanServer());
            jmxConnectorServer.start();
            logger.info("JMXServerManager JMX Service URL : " + jmxServiceURL.toString());
        } catch (Throwable throwable) {
            logger.error("Failed to start CarbonJMXComponent.", throwable);
        }
    }

    public void stop() throws Exception {
        if (jmxConnectorServer != null) {
            jmxConnectorServer.stop();
            UnicastRemoteObject.unexportObject(rmiRegistry, true); // Stop the RMI registry
        }
    }
}
