import java.security.MessageDigest

plugins { `java-library` }

dependencies {
    api(project(":core"))
    implementation(project(":saml"))
    implementation(project(":store"))
    implementation(libs.jackson.databind)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

// Result JSON remains self-contained when the runner is used outside the API module.
tasks.processResources {
    from(rootProject.file("LICENSES")) { into("META-INF/samlscope/LICENSES") }
}

val verifyLicenseMaterials = tasks.register("verifyLicenseMaterials") {
    doLast {
        // JVM-only verification also runs in the production image, which has no Python tooling.
        val parser = groovy.json.JsonSlurper()
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString("") { "%02x".format(it) }
        val index = parser.parse(rootProject.file("LICENSES/material-index.json")) as Map<*, *>
        val inputs = index["input_sha256"] as Map<*, *>
        inputs.forEach { (path, digest) ->
            check(sha(rootProject.file(path.toString()).readBytes()) == digest) {
                "Stale license material index for $path; regenerate with dev/licensing/materials.py"
            }
        }
        val registry = parser.parse(rootProject.file("LICENSES/source-notices.json")) as Map<*, *>
        (registry["sources"] as List<*>).forEach {
            val source = it as Map<*, *>
            check(sha(source["notice_text"].toString().toByteArray(Charsets.UTF_8)) == source["notice_text_sha256"]) {
                "Source notice digest mismatch: ${source["id"]}"
            }
        }
        val original = registry["original_content"] as Map<*, *>
        check(original["license_text"] == rootProject.file("LICENSES/CC-BY-SA-4.0.txt").readText())
    }
}
tasks.processResources { dependsOn(verifyLicenseMaterials) }
