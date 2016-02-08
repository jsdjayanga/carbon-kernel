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
package org.wso2.carbon.axis2.runtime.internal;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.TransportInDescription;
import org.apache.axis2.engine.ListenerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.axis2.runtime.transport.DummyTransportListener;
import org.wso2.carbon.kernel.runtime.Runtime;
import org.wso2.carbon.kernel.runtime.RuntimeState;
import org.wso2.carbon.kernel.runtime.exception.RuntimeServiceException;
import org.wso2.carbon.kernel.transports.CarbonTransport;

import java.io.File;
import java.nio.file.Paths;

/**
 * Axis2Runtime
 */
public class Axis2Runtime implements Runtime {
    private static final Logger logger = LoggerFactory.getLogger(Axis2Runtime.class);
    private RuntimeState runtimeState = RuntimeState.PENDING;
    private String axis2FilePath;

    @Override
    public void init() throws RuntimeServiceException {
        axis2FilePath = Paths.get(System.getProperty("carbon.home"), "conf", "axis2", "axis2.xml").toString();
        File file = new File(axis2FilePath);
        if (!file.exists()) {
            throw new RuntimeServiceException("Unable to find Axis.xml file in location " +
                    "'[PRODUCT_HOME]/conf/axis2/axis2.xml'");
        }
        runtimeState = RuntimeState.INACTIVE;
    }

    @Override
    public void start() throws RuntimeServiceException {

        ConfigurationContext configurationContext;
        try {
            configurationContext = ConfigurationContextFactory.
                    createConfigurationContextFromFileSystem(null, axis2FilePath);
        } catch (AxisFault axisFault) {
            throw new RuntimeServiceException("Failed to initialize Axis2 engine with the given axis2.xml", axisFault);
        }

        DataHolder.getInstance().setConfigurationContext(configurationContext);

        ListenerManager listenerManager = new ListenerManager();
        listenerManager.init(DataHolder.getInstance().getConfigurationContext());
        listenerManager.start();

        for (CarbonTransport carbonTransport : DataHolder.getInstance().getCarbonTransportList()) {
            if (configurationContext != null) {
                String transportId = carbonTransport.getId();
                TransportInDescription transportInDescription =
                        new TransportInDescription(transportId.substring(transportId.indexOf("-") + 1));
                DummyTransportListener dummyTransportListener = new DummyTransportListener();
                transportInDescription.setReceiver(dummyTransportListener);
                try {
                    configurationContext.getAxisConfiguration().addTransportIn(transportInDescription);
                    configurationContext.getListenerManager().addListener(transportInDescription, false);
                } catch (AxisFault axisFault) {
                    logger.error("Error while configuring transport", axisFault);
                }
            }
        }

        runtimeState = RuntimeState.ACTIVE;
    }

    @Override
    public void stop() throws RuntimeServiceException {
        // TODO : Need to stop all services in Axis2
        runtimeState = RuntimeState.INACTIVE;
    }

    @Override
    public void beginMaintenance() throws RuntimeServiceException {
        runtimeState = RuntimeState.MAINTENANCE;
    }

    @Override
    public void endMaintenance() throws RuntimeServiceException {
        runtimeState = RuntimeState.INACTIVE;
    }

    @Override
    public Enum<RuntimeState> getState() {
        return runtimeState;
    }

    @Override
    public void setState(RuntimeState runtimeState) {
        this.runtimeState = runtimeState;
    }
}
