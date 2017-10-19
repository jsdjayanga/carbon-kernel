/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.launcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.base.CarbonComponent;
import org.wso2.carbon.launcher.config.CarbonLaunchConfig;

import java.text.DecimalFormat;
import java.util.ServiceLoader;
import java.util.stream.Stream;

import static org.wso2.carbon.launcher.Constants.CARBON_START_TIME;

/**
 * Launches a Carbon instance.
 *
 * @since 5.0.0
 */
public class CarbonServer {

    private static final Logger logger = LoggerFactory.getLogger(CarbonServer.class);

    private ServerStatus serverStatus;
    boolean stopServerWait = false;

    /**
     * Starts a Carbon server instance. This method returns only after the server instance stops completely.
     *
     * @throws Exception if error occurred
     */
    public void start() throws Exception {
        logger.info("Starting Carbon server instance.");

        // Sets the server start time.
        System.setProperty(CARBON_START_TIME, Long.toString(System.currentTimeMillis()));

        try {
            setServerCurrentStatus(ServerStatus.STARTING);
            // Notify Carbon server start.
            dispatchEvent(CarbonServerEvent.STARTING);

            ServiceLoader<CarbonComponent> serviceLoader = ServiceLoader.load(CarbonComponent.class);
            Stream<ServiceLoader.Provider<CarbonComponent>> serviceProviderStream = serviceLoader.stream();
            serviceProviderStream.parallel().forEach(carbonComponentProvider -> {
                try {
                    logger.info("Starting CarbonComponent : '" + carbonComponentProvider.get().getName() + "'");
                    carbonComponentProvider.get().start();
                } catch (Exception e) {
                    logger.error("Error while starting CarbonComponent : '"
                            + carbonComponentProvider.get().getName() + "'", e);
                    throw new RuntimeException("Error while starting CarbonComponent : '"
                            + carbonComponentProvider.get().getName() + "'", e);
                }
            });

            setServerCurrentStatus(ServerStatus.STARTED);

            logServerStartupTime("ServerName");

            // This thread waits until the server is stopped.
            while (true) {
                Thread.sleep(5000);
                if (stopServerWait) {
                    break;
                }
            }

            setServerCurrentStatus(ServerStatus.STOPPING);
            // Notify Carbon server shutdown.
            dispatchEvent(CarbonServerEvent.STOPPING);

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Stop this Carbon server instance.
     */
    public void stop() {
        if (stopServerWait) {
            return;
        }

        logger.info("Stopping the OSGi framework.");

        stopServerWait = true;
    }

    /**
     * set status of Carbon server.
     */
    private void setServerCurrentStatus(ServerStatus status) {
        serverStatus = status;
    }

    /**
     * Check status of Carbon server.
     *
     * @return Server status
     */
    public ServerStatus getServerCurrentStatus() {
        return serverStatus;
    }

    /**
     * Notify Carbon server listeners about the given event.
     *
     * @param event number to notify
     */
    private void dispatchEvent(int event) {
        // TODO :  User SPI to load Listeners
//        CarbonServerEvent carbonServerEvent = new CarbonServerEvent(event, config);
//        config.getCarbonServerListeners().forEach(listener -> {
//            String eventName = (event == CarbonServerEvent.STARTING) ? "STARTING" : "STOPPING";
//            logger.info("Dispatching " + eventName + " event to " + listener.getClass().getName());
//            listener.notify(carbonServerEvent);
//        });
    }

    /**
     * Log the server start up time.
     *
     * @param serverName Server name to be in the log
     */
    public static void logServerStartupTime(String serverName) {
        double startTime = Long.parseLong(System.getProperty(Constants.START_TIME));
        double startupTime = (System.currentTimeMillis() - startTime) / 1000;

        DecimalFormat decimalFormatter = new DecimalFormat("#,##0.000");
        logger.info(serverName + " started in " + decimalFormatter.format(startupTime) + " sec");
    }
}
