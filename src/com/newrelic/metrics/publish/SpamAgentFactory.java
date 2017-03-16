package com.newrelic.metrics.publish;

import com.doodle.spam.SpamAgent;
import com.newrelic.metrics.publish.configuration.ConfigurationException;

import java.util.Map;

public class SpamAgentFactory extends AgentFactory {
    @Override
    public Agent createConfiguredAgent(Map<String, Object> properties) throws ConfigurationException {
        String name = (String) properties.get("name");
        String logFile = (String) properties.get("logFile");
        String dateFormat = (String) properties.get("dateFormat");
        String patternMethod = (String) properties.get("patternMethod");
        String patternEndpoint = (String) properties.get("patternEndpoint");
        String patternIpv4 = (String) properties.get("patternIpv4");
        String patternIpv6 = (String) properties.get("patternIpv6");

        if (name == null || logFile == null || dateFormat == null || patternMethod == null || patternEndpoint == null || patternIpv4 == null || patternIpv6 == null) {
            throw new ConfigurationException("Missing or null configuration parameters");
        }
        return new SpamAgent(name, logFile, dateFormat, patternMethod, patternEndpoint, patternIpv4, patternIpv6);
    }
}
