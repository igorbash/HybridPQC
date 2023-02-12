FROM maven:3-openjdk-17-slim AS build

WORKDIR /app
COPY pom.xml ./
COPY src ./src

RUN mvn -f pom.xml clean package

RUN ls target
FROM openjdk:17-slim

COPY --from=build /app/target/HybridPQC-1.0-SNAPSHOT.jar HybridPQC.jar

ENTRYPOINT ["java","-jar","HybridPQC.jar"]