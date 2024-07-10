plugins {
    kotlin("jvm") version "1.9.23"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation ("org.jetbrains.kotlin:kotlin-stdlib")
    implementation ("com.squareup.okhttp3:okhttp:4.9.1")
    implementation ("org.jsoup:jsoup:1.13.1")
    implementation ("org.bouncycastle:bcprov-jdk15on:1.68")
    implementation ("com.google.code.gson:gson:2.8.6")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}