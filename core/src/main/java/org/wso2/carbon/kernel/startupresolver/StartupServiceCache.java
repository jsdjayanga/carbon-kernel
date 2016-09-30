package org.wso2.carbon.kernel.startupresolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by jayanga on 9/28/16.
 */
public class StartupServiceCache {
    private Map<String, List<Object>> services = new HashMap<>();

    public synchronized void addService(String serviceApi, Object service) {
        List<Object> serviceList = services.get(serviceApi);
        if (serviceList == null) {
            serviceList = new ArrayList<>();
            services.put(serviceApi, serviceList);
        }
        serviceList.add(service);
    }

    public Map<String, List<Object>> getServices() {
        return services;
    }
}
