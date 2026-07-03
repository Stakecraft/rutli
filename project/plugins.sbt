// Fat-jar assembly so the driver + its deps land on the Canton classpath as one artifact.
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.3.1")

// NOTE: gRPC stubs for the FROST client are pre-generated (native protoc + protoc-gen-grpc-java)
// and checked into driver/src/main/java — see scripts/gen-grpc-java.sh. No sbt codegen plugin.
