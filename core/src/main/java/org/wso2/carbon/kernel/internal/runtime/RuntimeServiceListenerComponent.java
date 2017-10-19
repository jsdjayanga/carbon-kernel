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
package org.wso2.carbon.kernel.internal.runtime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.base.CarbonComponent;
import org.wso2.carbon.kernel.internal.DataHolder;
import org.wso2.carbon.kernel.jmx.MBeanRegistrator;
import org.wso2.carbon.kernel.runtime.Runtime;
import org.wso2.carbon.kernel.runtime.RuntimeService;

import java.util.ServiceLoader;
import java.util.stream.Stream;

/**
 * This service  component is responsible for retrieving the Runtime OSGi service and register each runtime
 * with runtime manager. It also acts as a RequiredCapabilityListener for all the Runtime capabilities, and
 * once they are available, it registers the RuntimeService as an OSGi service.
 *
 * @since 5.0.0
 */
public class RuntimeServiceListenerComponent implements CarbonComponent {
    public static final String COMPONENT_NAME = "carbon-runtime-mgt";
    private static final Logger logger = LoggerFactory.getLogger(RuntimeServiceListenerComponent.class);
    private RuntimeManager runtimeManager = new RuntimeManager();

    @Override
    public String getName() {
        return RuntimeServiceListenerComponent.class.getName();
    }

    @Override
    public boolean start() throws Exception {
        DataHolder.getInstance().setRuntimeManager(runtimeManager);
        ServiceLoader<Runtime> serviceLoader = ServiceLoader.load(Runtime.class);
        Stream<ServiceLoader.Provider<Runtime>> serviceProviderStream = serviceLoader.stream();
        serviceProviderStream.parallel().forEach(carbonComponentProvider -> {
            try {
                logger.info("Starting Runtime : '" + carbonComponentProvider.get() + "'");
                runtimeManager.registerRuntime(carbonComponentProvider.get());
            } catch (Exception e) {
                logger.error("Error while starting Runtime : '"
                        + carbonComponentProvider.get() + "'", e);
                throw new RuntimeException("Error while starting Runtime : '"
                        + carbonComponentProvider.get() + "'", e);
            }
        });
        RuntimeService runtimeService = new CarbonRuntimeService(runtimeManager);
        runtimeService.startRuntimes();
        MBeanRegistrator.registerMBean(runtimeService);
        return true;
    }

    @Override
    public boolean stop() throws Exception {
        return false;
    }
}
