# OkHttp driver image: the JVM/Android HTTP stack.
#
# OkHttp only negotiates HTTP/2 over TLS by default, so the driver selects
# Protocol.H2_PRIOR_KNOWLEDGE for cleartext URLs (see OkHttpDriver.java).
# Versions are pinned (OkHttp, Okio, Kotlin stdlib) so an upstream release
# cannot turn into an unexplained failure here. Jars are fetched from Maven
# Central at build time rather than committed to git.

FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY clients/okhttp/OkHttpDriver.java ./
RUN curl -fsSL -o okhttp.jar https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar \
 && curl -fsSL -o okio.jar https://repo1.maven.org/maven2/com/squareup/okio/okio-jvm/3.6.0/okio-jvm-3.6.0.jar \
 && curl -fsSL -o kotlin-stdlib.jar https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.9.22/kotlin-stdlib-1.9.22.jar \
 && curl -fsSL -o annotations.jar https://repo1.maven.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.jar \
 && javac -cp "okhttp.jar:okio.jar:kotlin-stdlib.jar:annotations.jar" \
        -d /out OkHttpDriver.java \
 && cp okhttp.jar okio.jar kotlin-stdlib.jar annotations.jar /out/

FROM eclipse-temurin:21-jre AS driver
COPY --from=build /out /app
ENTRYPOINT ["java", "-cp", "/app:/app/okhttp.jar:/app/okio.jar:/app/kotlin-stdlib.jar:/app/annotations.jar", "OkHttpDriver"]
