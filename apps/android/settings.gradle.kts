pluginManagement {
    repositories {
        google()
        maven(url = "https://maven-central.storage-download.googleapis.com/maven2")
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(
        org.gradle.api.initialization.resolve.RepositoriesMode.FAIL_ON_PROJECT_REPOS
    )
    repositories {
        google()
        maven(url = "https://maven-central.storage-download.googleapis.com/maven2")
        mavenCentral()
    }
}

rootProject.name = "sovereign-private-messenger-android"
include(":app")