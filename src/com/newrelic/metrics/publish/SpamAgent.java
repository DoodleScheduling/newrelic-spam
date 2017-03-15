package com.newrelic.metrics.publish;

import com.newrelic.metrics.publish.configuration.ConfigurationException;
import com.newrelic.metrics.publish.util.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SpamAgent extends Agent {

    private static final Logger logger = Logger.getLogger(SpamAgent.class);

    private static final String GUID = "com.doodle.spamnginx";
    private static final String VERSION = "1.0.0";

    // Agent configuration, retrieved from plugin.json
    private final String name;
    private final String command;

    // Regex patterns to match each part of the request
    private final Pattern patternMethod;
    private final Pattern patternIpv4;
    private final Pattern patternIpv6;
    private final Pattern patternEndpoint;


    public SpamAgent(String name, String logfile, String dateformat, String patternMethod, String patternEndpoint, String patternIpv4, String patternIpv6) throws ConfigurationException {
        super(GUID, VERSION);
        this.name = name;
        this.patternMethod = Pattern.compile(patternMethod);
        this.patternEndpoint = Pattern.compile(patternEndpoint);
        this.patternIpv4 = Pattern.compile(patternIpv4);
        this.patternIpv6 = Pattern.compile(patternIpv6);
        this.command = "grep \"$(date +'" + dateformat + "')\" " + logfile + " grep \"limiting requests\"";
    }

    // 2017/03/14 11:32:44 [error] 12528#12528: *999 limiting requests, excess: 5.898 by zone "protectedendpoints",
    // client: 127.0.0.1, server: _, request: "POST / HTTP/1.0", host: "localhost"

    @Override
    public String getAgentName() {
        return name;
    }

    @Override
    public void pollCycle() {
        List<Spam> requests = getSpamLogs();

        Set<String> uniqueIpv4 = new HashSet<>();
        Set<String> uniqueIpv6 = new HashSet<>();
        Set<String> uniqueEndpoints = new HashSet<>();
        Integer blockedPost = 0;
        Integer blockedPut = 0;
        Integer blockedDelete = 0;

        for (Spam spam : requests) {
            if (spam.getIpv4client() != null) uniqueIpv4.add(spam.getIpv4client());
            if (spam.getIpv6client() != null) uniqueIpv6.add(spam.getIpv6client());
            uniqueEndpoints.add(spam.getEndpoint());
            switch (spam.getMethod()) {
                case "POST":
                    blockedPost++;
                    break;
                case "DELETE":
                    blockedDelete++;
                    break;
                case "PUT":
                    blockedPut++;
            }
        }

        reportMetric("Blocked requests", "requests", requests.size());
        reportMetric("Unique Ipv4", "clients", uniqueIpv4.size());
        reportMetric("Unique Ipv6", "clients", uniqueIpv6.size());
        reportMetric("Blocked POST", "requests", blockedPost);
        reportMetric("Blocked DELETE", "requests", blockedDelete);
        reportMetric("Blocked PUT", "requests", blockedPut);
        reportMetric("Blocked endpoints", "endpoints", uniqueEndpoints.size());
    }

    private List<Spam> getSpamLogs() {
        List<Spam> logs = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            String line;

            // Read standard output, and save only the last line
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = br.readLine()) != null) {
                logs.add(parseSpam(line));
            }

            // Read standard error
            br = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            StringBuilder output = new StringBuilder();
            while ((line = br.readLine()) != null) {
                output.append(line);
                output.append(System.getProperty("line.separator"));
            }

            // Wait for the command to finish
            int returnCode = process.waitFor();
            if (returnCode != 0) {
                logger.error("Command '" + command + "' returned code: " + returnCode);
                if (output.length() > 0) {
                    logger.error("Standard error:");
                    logger.error(output);
                }
                throw new RuntimeException();
            }
        } catch (Exception e) {
            logger.error("Failed to execute " + command);
        }
        return logs;
    }

    private Spam parseSpam(String logentry) {
        Matcher matcherMethod = patternMethod.matcher(logentry);
        Matcher matcherEndpoint = patternEndpoint.matcher(logentry);
        Matcher matcherIpv4 = patternIpv4.matcher(logentry);
        Matcher matcherIpv6 = patternIpv6.matcher(logentry);
        String method = matcherMethod.group(1);
        String endpoint = matcherEndpoint.group(1);
        String ipv4 = matcherIpv4.group(1);
        String ipv6 = matcherIpv6.group(1);

        logger.debug("Parsed spam: method " + method + "endpoint: " + endpoint + " source: " + ipv4 + ipv6);
        return new Spam(method, endpoint, ipv4, ipv6);

    }
}
