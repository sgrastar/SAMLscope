import org.gradle.api.tasks.Exec

plugins { base }

val npmInstall = tasks.register<Exec>("npmInstall") {
    inputs.files("package.json", "package-lock.json")
    outputs.dir("node_modules")
    commandLine("npm", "ci", "--ignore-scripts")
}

val buildWeb = tasks.register<Exec>("buildWeb") {
    dependsOn(npmInstall)
    inputs.dir("src")
    inputs.dir("public")
    inputs.files("license-notices.mjs", "license-notices.d.mts")
    inputs.files(rootProject.files("LICENSE", "LICENSING.md"))
    inputs.dir(rootProject.file("LICENSES"))
    inputs.files("index.html", "package.json", "package-lock.json", "tsconfig.json", "vite.config.ts")
    outputs.dir(layout.buildDirectory.dir("dist"))
    commandLine("npm", "run", "build", "--", "--outDir", layout.buildDirectory.dir("dist").get().asFile.absolutePath)
}

val testWeb = tasks.register<Exec>("testWeb") {
    dependsOn(npmInstall)
    inputs.dir("src")
    inputs.dir("public")
    inputs.files("license-notices.mjs", "license-notices.d.mts")
    inputs.files(rootProject.files("LICENSE", "LICENSING.md"))
    inputs.dir(rootProject.file("LICENSES"))
    inputs.files("package.json", "package-lock.json", "tsconfig.json", "vite.config.ts")
    commandLine("npm", "test", "--", "--run")
}

tasks.named("assemble") { dependsOn(buildWeb) }
tasks.named("check") { dependsOn(testWeb, buildWeb) }
