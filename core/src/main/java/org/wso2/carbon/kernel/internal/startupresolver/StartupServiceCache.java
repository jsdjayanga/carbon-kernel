/*
*  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing,
*  software distributed under the License is distributed on an
*  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*  KIND, either express or implied.  See the License for the
*  specific language governing permissions and limitations
*  under the License.
*/
package org.wso2.carbon.kernel.internal.startupresolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * StartupServiceCache caches all the startup services against the component name given in the
 * ${@link org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener} and interface name of the services.
 *
 * @since 5.2.0
 */
public class StartupServiceCache {
    private static final Logger logger = LoggerFactory.getLogger(StartupServiceCache.class);

    private static StartupServiceCache ourInstance = new StartupServiceCache();
    private Map<String, Map<String, List<Object>>> startupServiceMap = new HashMap<>();

    public static StartupServiceCache getInstance() {
        return ourInstance;
    }

    private StartupServiceCache() {
    }

    /**
     * This method update the internal startup service cache with the given details.
     *
     * @param serviceListenerComponentName the name given in the
     *                                     ${@link org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener}.
     * @param iFace                        service interface name.
     * @param serviceInstance              service instance.
     */
    public void update(String serviceListenerComponentName, Class iFace, Object serviceInstance) {
        Map<String, List<Object>> componentServices = startupServiceMap.get(serviceListenerComponentName);
        if (componentServices == null) {
            logger.debug("Creating a Component Services Map for component {}", serviceListenerComponentName);
            componentServices = new HashMap<>();
            startupServiceMap.put(serviceListenerComponentName, componentServices);
        }

        List<Object> serviceInstances = componentServices.get(iFace.getName());
        if (serviceInstances == null) {
            logger.debug("Creating a Service Instance List for interface {} in component {}",
                    iFace, serviceListenerComponentName);
            serviceInstances = new ArrayList<>();
            componentServices.put(iFace.getName(), serviceInstances);
        }

        if (serviceInstances.indexOf(serviceInstance) == -1) {
            serviceInstances.add(serviceInstance);
        }
    }

    /**
     * This method returns a Map containing Lists of objects.
     *
     * @param serviceListenerComponentName the name given in the
     *                                     ${@link org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener}.
     * @return a Map containing Lists of service objects.
     */
    public Map<String, List<Object>> getCachedServices(String serviceListenerComponentName) {
        return Optional.ofNullable(startupServiceMap.get(serviceListenerComponentName)).orElse(new HashMap<>());
    }
}
