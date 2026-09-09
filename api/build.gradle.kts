plugins {
    application
}

dependencies {
    implementation(project(":core"))
    implementation(project(":saml"))
    implementation(project(":store"))
    implementation(project(":runner"))
    implementation(project(":peer"))
    implementation(libs.javalin)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.jsr310)
    implementation(libs.jackson.yaml)
    implementation(libs.nimbus.oidc)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

application {
    mainClass.set("com.samlscope.api.SamlScopeApplication")
    applicationName = "samlscope"
}

tasks.processResources {
    dependsOn(":web:buildWeb")
    from(project(":web").layout.buildDirectory.dir("dist")) {
        into("public")
    }
    from(rootProject.layout.projectDirectory.file("tests/coverage.yaml")) { into("catalog/tests") }
    from(rootProject.layout.projectDirectory.file("tests/specs.yaml")) { into("catalog/tests") }
    from(rootProject.layout.projectDirectory.file("tests/predicates.yaml")) { into("catalog/tests") }
    from(rootProject.layout.projectDirectory.file("tests/cases.yaml")) { into("catalog/tests") }
    from(rootProject.layout.projectDirectory.file("tests/feasibility.yaml")) { into("catalog/tests") }
    from(rootProject.layout.projectDirectory.file("tests/mutants/baselines.yaml")) { into("catalog/tests/mutants") }
    from(rootProject.layout.projectDirectory.file("tests/mutants/catalog.yaml")) { into("catalog/tests/mutants") }
    from(rootProject.layout.projectDirectory.file("tests/mutants/control-mutants.yaml")) { into("catalog/tests/mutants") }
    from(rootProject.layout.projectDirectory.dir("profiles")) { into("profiles") }
}
