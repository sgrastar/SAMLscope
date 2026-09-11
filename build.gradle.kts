import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.security.MessageDigest
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.Exec
import org.gradle.jvm.tasks.Jar
import org.gradle.api.file.DuplicatesStrategy
import org.gradle.jvm.toolchain.JavaLanguageVersion

plugins {
    base
}

group = "com.samlscope"
version = "0.1.0"

subprojects {
    group = rootProject.group
    version = rootProject.version

    pluginManager.withPlugin("application") {
        val externalJars = configurations.named("runtimeClasspath").get().incoming.artifactView {
            componentFilter { it is ModuleComponentIdentifier }
        }.files
        val inventoryFile = rootProject.file("web/public/licenses/java-dependencies.json")
        val permissionFile = rootProject.file("LICENSES/java-permissions.json")
        tasks.register("writeJavaLicenseInputs") {
            description = "Writes resolved external JAR paths for license inventory regeneration."
            doLast {
                val output = rootProject.layout.buildDirectory.file("java-license-inputs.json").get().asFile
                output.parentFile.mkdirs()
                output.writeText(JsonOutput.toJson(externalJars.files.sortedBy { it.name }.map { it.absolutePath }))
            }
        }
        val verifyJavaLicenseInventory = tasks.register("verifyJavaLicenseInventory") {
            description = "Rejects stale dependency notices before packaging the application."
            inputs.files(externalJars)
            inputs.file(inventoryFile)
            inputs.file(permissionFile)
            doLast {
                val inventory = JsonSlurper().parse(inventoryFile) as Map<*, *>
                val packages = inventory["packages"] as List<*>
                val reviewed = (JsonSlurper().parse(permissionFile) as Map<*, *>)["packages"] as Map<*, *>
                packages.forEach {
                    val entry = it as Map<*, *>
                    val permission = entry["permission"] as? Map<*, *>
                    check(permission != null && permission == reviewed[entry["file"]] &&
                        permission["jar_sha256"] == entry["sha256"] &&
                        permission["publication_status"] in listOf("GREEN", "YELLOW")) {
                        "Java dependency permission review is missing or stale: ${entry["file"]}"
                    }
                    val resourceReviews = permission["resource_reviews"] as? Map<*, *>
                    (entry["embedded_schemas"] as List<*>).forEach { value ->
                        val schema = value as Map<*, *>
                        val review = resourceReviews?.get(schema["file"]) as? Map<*, *>
                        check(review != null && review["sha256"] == schema["sha256"] &&
                            schema["review"] == review && schema["review_status"] == "REVIEWED_UPSTREAM_DISTRIBUTION_CONTEXT") {
                            "Embedded resource review is missing or stale: ${entry["file"]}!${schema["file"]}"
                        }
                    }
                }
                val recorded = packages.associate {
                    val entry = it as Map<*, *>
                    entry["file"].toString() to entry["sha256"].toString()
                }
                val actual = externalJars.files.associate { file ->
                    file.name to MessageDigest.getInstance("SHA-256").digest(file.readBytes())
                        .joinToString("") { "%02x".format(it) }
                }
                check(packages.size == recorded.size && recorded == actual) {
                    "Java license inventory is stale. Run :api:writeJavaLicenseInputs, then " +
                        ".venv/bin/python dev/licensing/java_dependencies.py --inputs-json build/java-license-inputs.json"
                }
            }
        }
        tasks.named("processResources") { dependsOn(verifyJavaLicenseInventory) }
        tasks.named("check") { dependsOn(verifyJavaLicenseInventory) }
    }

    pluginManager.withPlugin("java") {
        extensions.configure<JavaPluginExtension> {
            toolchain.languageVersion.set(JavaLanguageVersion.of(21))
            withSourcesJar()
        }

        // Keep the scope statement with every independently redistributed binary/source JAR.
        // API resources already contain these exact files; exclude duplicate copies there.
        tasks.withType<Jar>().configureEach {
            from(rootProject.files("LICENSE", "LICENSING.md")) {
                into("META-INF/samlscope")
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }
            from(rootProject.file("LICENSES/CC-BY-SA-4.0.txt")) {
                into("META-INF/samlscope/LICENSES")
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }
        }

        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            testLogging {
                events("failed", "skipped")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

tasks.named("check") {
    dependsOn(
        ":core:check",
        ":saml:check",
        ":store:check",
        ":runner:check",
        ":peer:check",
        ":api:check",
        ":web:check",
    )
}

val releasePolicyCheck = tasks.register<Exec>("releasePolicyCheck") {
    description = "Verifies signed G1/G2 approvals and all release policy artifacts."
    group = "verification"
    workingDir(rootDir)
    val python = providers.environmentVariable("PY")
        .orElse(layout.projectDirectory.file(".venv/bin/python").asFile.absolutePath)
    commandLine(python.get(), "tools/release_check.py")
    outputs.file(layout.buildDirectory.file("release-check-report.json"))
    outputs.upToDateWhen { false }
    mustRunAfter(tasks.named("check"))
}

val releasePolicyUnitTest = tasks.register<Exec>("releasePolicyUnitTest") {
    description = "Runs unit tests for the fail-closed release policy checker."
    group = "verification"
    workingDir(rootDir)
    val python = providers.environmentVariable("PY").orElse("python3")
    commandLine(
        python.get(), "-m", "unittest",
        "tools/tests/test_release_check.py", "dev/keycloak/test_smoke.py",
        "dev/keycloak/test_prepare_smoke_apple.py",
    )
}

tasks.named("check") {
    dependsOn(releasePolicyUnitTest)
}

tasks.register("releaseCheck") {
    description = "Runs the complete fail-closed verification required before a release or container publication."
    group = "verification"
    dependsOn(tasks.named("check"), releasePolicyCheck)
}
