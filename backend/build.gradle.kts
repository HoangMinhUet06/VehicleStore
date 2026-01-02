plugins {
    java
    id("org.springframework.boot") version "3.3.4"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {

    //Dev tools
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    // ===== CORE =====
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    // ===== OAUTH2  =====
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

    // ===== DB =====
    runtimeOnly("com.mysql:mysql-connector-j")

    // ===== DEV =====
    developmentOnly("org.springframework.boot:spring-boot-devtools")

    // ===== LOMBOK =====
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    // ===== TEST =====
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    //testImplementation("org.springframework.security:spring-security-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
