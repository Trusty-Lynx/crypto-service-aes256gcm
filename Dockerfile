# ---- Build stage: compile Kotlin + assemble the Ktor fat jar ----
FROM gradle:9.1.0-jdk21 AS build
WORKDIR /build

# Cache dependencies first (only re-resolves when build scripts change).
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
RUN gradle --no-daemon dependencies > /dev/null 2>&1 || true

# Build the fat jar (io.ktor.plugin provides buildFatJar).
COPY src ./src
RUN gradle --no-daemon buildFatJar

# ---- Run stage: slim JRE with just the jar ----
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Non-root user for safety.
RUN groupadd -r app && useradd -r -g app app

COPY --from=build /build/build/libs/*-all.jar app.jar
RUN chown app:app app.jar
USER app

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
