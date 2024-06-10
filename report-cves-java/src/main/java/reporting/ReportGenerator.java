package reporting;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ReportGenerator {

    private static final String URL = "https://api.scout.docker.com/v1/graphql";

    public static final String DOCKER_ORG = System.getenv("DOCKER_ORG");
    private static final String DOCKER_TOKEN = System.getenv("DOCKER_TOKEN");

    public static final ObjectMapper objectMapper = new ObjectMapper();

    public static String readResource(String resourceName) throws IOException, URISyntaxException {
        return new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(resourceName).toURI())), java.nio.charset.StandardCharsets.UTF_8);
    }

    public static JsonNode graphQlRequest(String queryName, Map<String, Object> variables) throws Exception {

        if (DOCKER_TOKEN == null) {
            throw new Exception("DOCKER_TOKEN environment variable not set.");
        }

        HttpClient client = HttpClient.newHttpClient();

        Map<String, Object> bodyMap = Map.of(
                "query", readResource(queryName),
                "variables", variables
        );

        String requestBody = objectMapper.writeValueAsString(bodyMap);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(URL))
                .header("Authorization", "Bearer " + DOCKER_TOKEN)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            if (response.statusCode() == 401) {
                throw new Exception("401 status running GraphQL request. Is your DOCKER_TOKEN valid / expired?");
            }
            throw new Exception(String.format("Failed to run GraphQL request. Response code [%d]", response.statusCode()));
        }

        return objectMapper.readTree(response.body());
    }

    public static JsonNode streamImages() throws Exception {

        if (DOCKER_ORG == null) {
            throw new Exception("DOCKER_ORG environment variable not set.");
        }

        final int PAGE_SIZE = 25;

        Map<String, Object> variables = Map.of("organization", DOCKER_ORG, "pageSize", PAGE_SIZE);

        System.out.println("Requesting streamImages page 1");
        JsonNode streamImages = graphQlRequest("queries/stream-images.query", variables)
                .path("data")
                .path("streamImages");
        int totalCount = streamImages.path("paging").path("totalCount").intValue();
        ArrayNode itemsNode = (ArrayNode) streamImages.path("items");

        int pages = (int)Math.ceil((double)totalCount / PAGE_SIZE);

        if (itemsNode.size() < totalCount) {
            for (int page = 2; page <= pages; page++) {
                System.out.println(String.format("Requesting streamImages page %d / %d", page, pages));
                variables = Map.of("organization", DOCKER_ORG, "pageSize", PAGE_SIZE, "page", page);
                ArrayNode newStreamImages = (ArrayNode) graphQlRequest("queries/stream-images.query", variables)
                        .path("data")
                        .path("streamImages")
                        .path("items");
                itemsNode.addAll(newStreamImages);
            }
        }

        return itemsNode;
    }

    public static JsonNode imageVulnerabilities(String digest) throws Exception {
        Map<String, Object> variables = Map.of("organization", DOCKER_ORG, "digest", digest);

        return graphQlRequest("queries/image-vulnerabilities.query", variables)
                .path("data")
                .path("imageVulnerabilitiesByDigest")
                .path("vulnerabilities");
    }

    public static List<CveResult> generateReportData() throws Exception {
        JsonNode images = streamImages();

        if (images.size() == 0) {
            throw new Exception("No images found for org/stream.");
        }

        System.out.println(String.format("Found %d images.", images.size()));

        List<CveResult> results = new ArrayList<>();
        for (JsonNode image : images) {
            String digest = image.path("digest").asText();
            String repoName = image.path("repository").path("repoName").asText();
            System.out.println(String.format("Getting vulnerabilities for image %s@%s", repoName, digest));
            JsonNode packageVulns = imageVulnerabilities(digest);
            for (JsonNode packageVuln : packageVulns) {
                for (JsonNode vuln : packageVuln.path("vulnerabilities")) {
                    String severity = vuln.path("cvss").path("severity").asText();
                    if ("CRITICAL".equals(severity) || "HIGH".equals(severity)) {
                        String id = vuln.path("sourceId").asText();
                        String description = vuln.path("description").asText();
                        Double epss = vuln.path("epss").path("score").asDouble();
                        CveResult result = new CveResultBuilder()
                                .setCveId(id)
                                .setDigest(digest)
                                .setRepoName(repoName)
                                .setSummary(description)
                                .setSeverity(severity)
                                .setEpss(epss)
                                .createCveResult();
                        results.add(result);
                    }
                }
            }
        }

        return results;
    }

    private static void runReport() throws Exception {

        List<CveResult> cveResults = generateReportData();

        // Transform in report format here, eg. CSV
        for (CveResult result : cveResults) {
            System.out.println(result);
        }

        return;
    }

    public static void main(String[] args) throws Exception {
        ReportGenerator.runReport();
    }

    public static class CveResult {
        private String cveId;
        private String digest;
        private String repoName;
        private String severity;
        private Double epss;
        private String summary;


        public CveResult(String cveId, String digest, String repoName, String severity, Double epss, String summary) {
            this.cveId = cveId;
            this.digest = digest;
            this.repoName = repoName;
            this.severity = severity;
            this.epss = epss;
            this.summary = summary;
        }

        public String getCveId() {
            return cveId;
        }

        public String getDigest() {
            return digest;
        }

        public String getRepoName() {
            return repoName;
        }

        public String getSeverity() {
            return severity;
        }

        public Double getEpss() {
            return epss;
        }

        public String getSummary() {
            return summary;
        }

        @Override
        public String toString() {
            return "CveResult{" +
                    "cveId='" + cveId + '\'' +
                    ", digest='" + digest + '\'' +
                    ", repoName='" + repoName + '\'' +
                    ", severity='" + severity + '\'' +
                    ", epss='" + epss + '\'' +
                    ", summary='" + summary + '\'' +
                    '}';
        }
    }

    public static class CveResultBuilder {
        private String cveId;
        private String digest;
        private String repoName;
        private String severity;
        private Double epss;
        private String summary;

        public CveResultBuilder setCveId(String cveId) {
            this.cveId = cveId;
            return this;
        }

        public CveResultBuilder setDigest(String digest) {
            this.digest = digest;
            return this;
        }

        public CveResultBuilder setRepoName(String repoName) {
            this.repoName = repoName;
            return this;
        }

        public CveResultBuilder setSeverity(String severity) {
            this.severity = severity;
            return this;
        }

        public CveResultBuilder setEpss(Double epss) {
            this.epss = epss;
            return this;
        }

        public CveResultBuilder setSummary(String summary) {
            this.summary = summary;
            return this;
        }

        public ReportGenerator.CveResult createCveResult() {
            return new ReportGenerator.CveResult(cveId, digest, repoName, severity, epss, summary);
        }
    }
}
