FROM openjdk:8-jre-alpine
EXPOSE 8080
COPY ./target/gateway-0.0.1-SNAPSHOT.jar gateway-0.0.1-SNAPSHOT.jar
CMD ["java", "-jar", "gateway-0.0.1-SNAPSHOT.jar"]