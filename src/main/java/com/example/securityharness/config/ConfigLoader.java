package com.example.securityharness.config;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

public final class ConfigLoader {

    private final ObjectMapper mapper;

    private ConfigLoader(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public static ConfigLoader yaml() {
        return new ConfigLoader(YAMLMapper.builder()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
                .build());
    }

    public static ConfigLoader json() {
        return new ConfigLoader(JsonMapper.builder()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .build());
    }

    public <T> T load(Path path, Class<T> type) throws ConfigLoadException {
        String text;
        try {
            text = Files.readString(path);
        } catch (NoSuchFileException e) {
            throw new ConfigLoadException("File not found: " + path, e);
        } catch (IOException e) {
            throw new ConfigLoadException("Could not read file: " + path, e);
        }
        return parse(text, path.toString(), type);
    }

    /** Loads a config packaged inside the jar, independent of the process working directory. */
    public <T> T loadResource(String resourceName, Class<T> type) throws ConfigLoadException {
        try (InputStream in = getClass().getResourceAsStream(resourceName)) {
            if (in == null) {
                throw new ConfigLoadException("Resource not found: " + resourceName, null);
            }
            return parse(new String(in.readAllBytes(), StandardCharsets.UTF_8), resourceName, type);
        } catch (IOException e) {
            throw new ConfigLoadException("Could not read resource: " + resourceName, e);
        }
    }

    private <T> T parse(String text, String source, Class<T> type) throws ConfigLoadException {
        try {
            return mapper.readValue(text, type);
        } catch (DatabindException e) {
            throw new ConfigLoadException("Invalid config in " + source + ": " + e.getOriginalMessage(), e);
        } catch (JacksonException e) {
            throw new ConfigLoadException("Malformed config in " + source + ": " + e.getMessage(), e);
        }
    }
}
