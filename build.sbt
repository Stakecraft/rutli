// rutli — Canton KMS Driver (Phase 0 spike)
//
// Canton community artifacts (kms-driver-api, kms-driver-testing) are NOT on Maven Central.
// Resolve them one of two ways (see docs/phase-0-spike.md):
//   (a) Build them locally from a Canton checkout at the pinned tag and `publishLocal`
//       (resolved via Resolver.mavenLocal / the ivy local repo below). This is the reliable path.
//   (b) Digital Asset's JFrog Artifactory, if you have access — set CANTON_ARTIFACTORY to the
//       exact repo URL from the KMS Driver guide.

ThisBuild / scalaVersion := "2.13.16"
ThisBuild / organization := "com.stakecraft"
ThisBuild / version      := "0.0.1-SNAPSHOT"

// Pin to the Canton release the target nodes run. Latest stable at time of writing: tag v3.5.6.
// NOTE on coordinates: building the v3.5.6 tag locally publishes the artifacts as
//   com.daml %% kms-driver-api % 3.6.0-SNAPSHOT
// (the in-repo fallback version string; Digital Asset injects real release versions only in CI via
// RELEASE_SUFFIX). The artifacts ARE from the v3.5.6 tag. DA's Artifactory publishes the same
// modules under release versions — adjust cantonOrg/cantonVersion if resolving from there.
val cantonOrg       = "com.daml"
val cantonVersion   = "3.6.0-SNAPSHOT"
val bouncyCastleVer = "1.78.1"

lazy val driver = (project in file("driver"))
  .settings(
    name := "rutli-driver",
    resolvers ++= Seq(
      Resolver.mavenLocal,
      Resolver.defaultLocal, // ivy local — where `publishLocal` puts the Canton API jars
    ) ++ sys.env
      .get("CANTON_ARTIFACTORY")
      .map(url => ("DigitalAsset" at url))
      .toSeq,
    libraryDependencies ++= Seq(
      cantonOrg %% "kms-driver-api" % cantonVersion,
      // Versions aligned to what kms-driver-api (v3.5.6) was built against — see its ivy.xml:
      // pureconfig-core 0.14.0, opentelemetry-api 1.60.1. The umbrella pureconfig artifact adds
      // pureconfig-generic, needed for the semiauto config derivation in the factory.
      "io.opentelemetry"       % "opentelemetry-api" % "1.60.1",
      "com.github.pureconfig" %% "pureconfig"        % "0.14.0",
      "org.slf4j"              % "slf4j-api"         % "2.0.13",
      // Crypto for the Phase 0 SoftwareBackend (never for production).
      "org.bouncycastle"       % "bcprov-jdk18on"    % bouncyCastleVer,
      "org.bouncycastle"       % "bcpkix-jdk18on"    % bouncyCastleVer,
      "org.scalatest" %% "scalatest" % "3.2.19" % Test,
    ),
    // The upstream conformance suite (kms-driver-testing) transitively drags in a large slice of
    // Canton (community-base, daml-lf, ...), whose local publishing requires the `dpm` toolchain.
    // Gate it behind CONFORMANCE=1 so plain `sbt driver/test` runs the self-contained unit specs.
    // With CONFORMANCE=1 (and the full module set publishLocal'd), the conformance suite compiles
    // and runs too.
    libraryDependencies ++= (
      if (sys.env.contains("CONFORMANCE"))
        Seq(cantonOrg %% "kms-driver-testing" % cantonVersion % Test)
      else Seq.empty
    ),
    Test / unmanagedSources / excludeFilter := (
      if (sys.env.contains("CONFORMANCE")) NothingFilter: FileFilter
      else ("*ConformanceTest.scala": FileFilter)
    ),
    // Fat jar so the driver + BouncyCastle land on the Canton classpath as one artifact.
    assembly / assemblyJarName := "rutli-driver.jar",
    assembly / assemblyMergeStrategy := {
      case PathList("META-INF", "services", _*) => MergeStrategy.concat
      case PathList("META-INF", _*)             => MergeStrategy.discard
      case "reference.conf"                     => MergeStrategy.concat
      case _                                    => MergeStrategy.first
    },
  )
