FROM maven:3-openjdk-17-slim

COPY pom.xml ./
COPY src ./src

RUN mvn compile

ENTRYPOINT ["mvn", "exec:java", "-Dexec.mainClass=Main"]
