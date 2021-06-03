import org.gradle.jvm.tasks.Jar

plugins {
    kotlin("jvm") version "1.4.10"
}

val projectVersion = "0.1.0"

repositories {
    mavenCentral()
}

sourceSets {
    main {
        java.srcDirs("src/main/java")
    }
}

dependencies {
    implementation("net.portswigger.burp.extender:burp-extender-api:2.1")
    implementation("com.beust:klaxon:5.5")
}

val fatJar = task("fatJar", type = Jar::class) {
    archiveBaseName.set("${project.name}-${projectVersion}")
    dependsOn(configurations.runtimeClasspath)
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    with(tasks.jar.get() as CopySpec)
}

tasks {
    "build" {
        dependsOn(fatJar)
    }
}

/**
 * Remember to reload the project in the Gradle window if changing this file!
 */