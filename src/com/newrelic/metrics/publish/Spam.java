package com.newrelic.metrics.publish;

import java.util.Date;

public class Spam {
    private final String method;
    private final String endpoint;
    private final String ipv4client;
    private final String ipv6client;

    public Spam(String method, String endpoint, String ipv4client, String ipv6client) {
        this.method = method;
        this.endpoint = endpoint;
        this.ipv4client = ipv4client;
        this.ipv6client = ipv6client;
    }

    public String getMethod() {
        return method;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getIpv4client() {
        return ipv4client;
    }

    public String getIpv6client() {
        return ipv6client;
    }
}
