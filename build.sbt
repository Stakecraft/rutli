// rutli — Canton KMS Driver (Phase 0 spike)
//
// Canton community artifacts (kms-driver-api, kms-driver-testing) are NOT on Maven Central.
// Resolve them one of two ways (see docs/phase-0-spike.md):
//   (a) Build them locally from a Canton checkout at the pinned tag and `publishLocal`
//       (resolved via Resolver.mavenLocal / the ivy local repo below). This is the reliable path.
//   (b) Digital Asset's JFrog Artifactory, if you have access — set CANTON_ARTIFACTORY to the
//       exact repo URL from the KMS Driver guide.

// Must be >= the scala-library Canton's artifacts were built with (SIP-51, backwards-only binary
// compatibility). Canton v3.6.1 builds on 2.13.18.
ThisBuild / scalaVersion := "2.13.18"
ThisBuild / organization := "com.stakecraft"
ThisBuild / version      := "0.4.0-rc.2"

// Canton nodes run on Java 17. Pin the bytecode target so the driver jar loads there even when the
// build machine's default JDK is newer (class-file version skew otherwise breaks at runtime).
ThisBuild / javacOptions  ++= Seq("--release", "17")
ThisBuild / scalacOptions ++= Seq("-release", "17")

// Pin to the Canton release the target nodes run. Splice DevNet bundles Canton 3.6.1 for
// validators (2026-10), so the conformance target is tag v3.6.1. The driver SPI (kms-driver-api)
// is byte-identical between v3.5.6 and v3.6.1, so the driver itself works on both lines.
// NOTE on coordinates: building the v3.6.1 tag locally publishes the artifacts as
//   com.daml %% kms-driver-api % 3.7.0-SNAPSHOT
// (the in-repo fallback version string; Digital Asset injects real release versions only in CI via
// RELEASE_SUFFIX). The artifacts ARE from the v3.6.1 tag. DA's Artifactory publishes the same
// modules under release versions — adjust cantonOrg/cantonVersion if resolving from there.
val cantonOrg       = "com.daml"
val cantonVersion   = "3.7.0-SNAPSHOT"
// The BouncyCastle Canton 3.6.1 ships (shared_dependencies.json). The release launcher puts
// Canton's jar ahead of the driver's (bin/canton: `-cp canton.jar:$EXTRA_CLASSPATH`), so at runtime
// the driver runs on Canton's BouncyCastle whatever version it bundles; testing against the same
// one matters for the ECIES path, which completes decryption in BouncyCastle's own IESEngine.
val bouncyCastleVer = "1.85"
val grpcVersion     = "1.82.1"
val protobufVersion = "4.29.3"

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
      // Versions aligned to what kms-driver-api (v3.6.1) was built against — see its ivy.xml:
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
    // gRPC client for the FROST cosigner cluster. The Java stubs are generated ONCE from the shared
    // proto (frost/cosigner/proto/cosigner.proto) with native protoc + protoc-gen-grpc-java and
    // checked in under driver/src/main/java (regenerate with scripts/gen-grpc-java.sh). We do NOT
    // use the sbt-protoc/scalapb bridge — its socket-based codegen plugin hangs in some sandboxes.
    libraryDependencies ++= Seq(
      "io.grpc"             % "grpc-netty-shaded" % grpcVersion,
      "io.grpc"             % "grpc-protobuf"     % grpcVersion,
      "io.grpc"             % "grpc-stub"         % grpcVersion,
      // In-process transport: lets the driver tests drive a fake cosigner without a TLS listener.
      "io.grpc"             % "grpc-inprocess"    % grpcVersion % Test,
      "com.google.protobuf" % "protobuf-java"     % protobufVersion,
      // javax.annotation.Generated referenced by the generated grpc stubs (compile-time only).
      "org.apache.tomcat"   % "annotations-api"   % "6.0.53" % Provided,
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
