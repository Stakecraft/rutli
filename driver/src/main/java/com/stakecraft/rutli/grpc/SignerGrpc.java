package com.stakecraft.rutli.grpc;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
 * backend) calls. The node it connects to acts as the session leader for that request.
 * </pre>
 */
@io.grpc.stub.annotations.GrpcGenerated
public final class SignerGrpc {

  private SignerGrpc() {}

  public static final java.lang.String SERVICE_NAME = "rutli.cosigner.v1.Signer";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.HealthRequest,
      com.stakecraft.rutli.grpc.HealthReply> getHealthMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Health",
      requestType = com.stakecraft.rutli.grpc.HealthRequest.class,
      responseType = com.stakecraft.rutli.grpc.HealthReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.HealthRequest,
      com.stakecraft.rutli.grpc.HealthReply> getHealthMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.HealthRequest, com.stakecraft.rutli.grpc.HealthReply> getHealthMethod;
    if ((getHealthMethod = SignerGrpc.getHealthMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getHealthMethod = SignerGrpc.getHealthMethod) == null) {
          SignerGrpc.getHealthMethod = getHealthMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.HealthRequest, com.stakecraft.rutli.grpc.HealthReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Health"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.HealthRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.HealthReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Health"))
              .build();
        }
      }
    }
    return getHealthMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GroupKeyRequest,
      com.stakecraft.rutli.grpc.GroupKeyReply> getGroupKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GroupKey",
      requestType = com.stakecraft.rutli.grpc.GroupKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.GroupKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GroupKeyRequest,
      com.stakecraft.rutli.grpc.GroupKeyReply> getGroupKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GroupKeyRequest, com.stakecraft.rutli.grpc.GroupKeyReply> getGroupKeyMethod;
    if ((getGroupKeyMethod = SignerGrpc.getGroupKeyMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getGroupKeyMethod = SignerGrpc.getGroupKeyMethod) == null) {
          SignerGrpc.getGroupKeyMethod = getGroupKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.GroupKeyRequest, com.stakecraft.rutli.grpc.GroupKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GroupKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.GroupKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.GroupKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("GroupKey"))
              .build();
        }
      }
    }
    return getGroupKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgRequest,
      com.stakecraft.rutli.grpc.DkgReply> getDkgMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Dkg",
      requestType = com.stakecraft.rutli.grpc.DkgRequest.class,
      responseType = com.stakecraft.rutli.grpc.DkgReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgRequest,
      com.stakecraft.rutli.grpc.DkgReply> getDkgMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgRequest, com.stakecraft.rutli.grpc.DkgReply> getDkgMethod;
    if ((getDkgMethod = SignerGrpc.getDkgMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getDkgMethod = SignerGrpc.getDkgMethod) == null) {
          SignerGrpc.getDkgMethod = getDkgMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgRequest, com.stakecraft.rutli.grpc.DkgReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Dkg"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Dkg"))
              .build();
        }
      }
    }
    return getDkgMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRequest,
      com.stakecraft.rutli.grpc.SignReply> getSignMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Sign",
      requestType = com.stakecraft.rutli.grpc.SignRequest.class,
      responseType = com.stakecraft.rutli.grpc.SignReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRequest,
      com.stakecraft.rutli.grpc.SignReply> getSignMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRequest, com.stakecraft.rutli.grpc.SignReply> getSignMethod;
    if ((getSignMethod = SignerGrpc.getSignMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getSignMethod = SignerGrpc.getSignMethod) == null) {
          SignerGrpc.getSignMethod = getSignMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.SignRequest, com.stakecraft.rutli.grpc.SignReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Sign"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Sign"))
              .build();
        }
      }
    }
    return getSignMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshRequest,
      com.stakecraft.rutli.grpc.RefreshReply> getRefreshMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Refresh",
      requestType = com.stakecraft.rutli.grpc.RefreshRequest.class,
      responseType = com.stakecraft.rutli.grpc.RefreshReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshRequest,
      com.stakecraft.rutli.grpc.RefreshReply> getRefreshMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshRequest, com.stakecraft.rutli.grpc.RefreshReply> getRefreshMethod;
    if ((getRefreshMethod = SignerGrpc.getRefreshMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getRefreshMethod = SignerGrpc.getRefreshMethod) == null) {
          SignerGrpc.getRefreshMethod = getRefreshMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.RefreshRequest, com.stakecraft.rutli.grpc.RefreshReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Refresh"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.RefreshRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.RefreshReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Refresh"))
              .build();
        }
      }
    }
    return getRefreshMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyStatusRequest,
      com.stakecraft.rutli.grpc.KeyStatusReply> getKeyStatusMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "KeyStatus",
      requestType = com.stakecraft.rutli.grpc.KeyStatusRequest.class,
      responseType = com.stakecraft.rutli.grpc.KeyStatusReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyStatusRequest,
      com.stakecraft.rutli.grpc.KeyStatusReply> getKeyStatusMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyStatusRequest, com.stakecraft.rutli.grpc.KeyStatusReply> getKeyStatusMethod;
    if ((getKeyStatusMethod = SignerGrpc.getKeyStatusMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getKeyStatusMethod = SignerGrpc.getKeyStatusMethod) == null) {
          SignerGrpc.getKeyStatusMethod = getKeyStatusMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.KeyStatusRequest, com.stakecraft.rutli.grpc.KeyStatusReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "KeyStatus"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyStatusRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyStatusReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("KeyStatus"))
              .build();
        }
      }
    }
    return getKeyStatusMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonySignTestRequest,
      com.stakecraft.rutli.grpc.CeremonySignTestReply> getCeremonySignTestMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonySignTest",
      requestType = com.stakecraft.rutli.grpc.CeremonySignTestRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonySignTestReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonySignTestRequest,
      com.stakecraft.rutli.grpc.CeremonySignTestReply> getCeremonySignTestMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonySignTestRequest, com.stakecraft.rutli.grpc.CeremonySignTestReply> getCeremonySignTestMethod;
    if ((getCeremonySignTestMethod = SignerGrpc.getCeremonySignTestMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getCeremonySignTestMethod = SignerGrpc.getCeremonySignTestMethod) == null) {
          SignerGrpc.getCeremonySignTestMethod = getCeremonySignTestMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonySignTestRequest, com.stakecraft.rutli.grpc.CeremonySignTestReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonySignTest"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonySignTestRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonySignTestReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("CeremonySignTest"))
              .build();
        }
      }
    }
    return getCeremonySignTestMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CapabilitiesRequest,
      com.stakecraft.rutli.grpc.CapabilitiesReply> getCapabilitiesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Capabilities",
      requestType = com.stakecraft.rutli.grpc.CapabilitiesRequest.class,
      responseType = com.stakecraft.rutli.grpc.CapabilitiesReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CapabilitiesRequest,
      com.stakecraft.rutli.grpc.CapabilitiesReply> getCapabilitiesMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CapabilitiesRequest, com.stakecraft.rutli.grpc.CapabilitiesReply> getCapabilitiesMethod;
    if ((getCapabilitiesMethod = SignerGrpc.getCapabilitiesMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getCapabilitiesMethod = SignerGrpc.getCapabilitiesMethod) == null) {
          SignerGrpc.getCapabilitiesMethod = getCapabilitiesMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CapabilitiesRequest, com.stakecraft.rutli.grpc.CapabilitiesReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Capabilities"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CapabilitiesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CapabilitiesReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Capabilities"))
              .build();
        }
      }
    }
    return getCapabilitiesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GenerateKeyRequest,
      com.stakecraft.rutli.grpc.GenerateKeyReply> getGenerateKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GenerateKey",
      requestType = com.stakecraft.rutli.grpc.GenerateKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.GenerateKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GenerateKeyRequest,
      com.stakecraft.rutli.grpc.GenerateKeyReply> getGenerateKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.GenerateKeyRequest, com.stakecraft.rutli.grpc.GenerateKeyReply> getGenerateKeyMethod;
    if ((getGenerateKeyMethod = SignerGrpc.getGenerateKeyMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getGenerateKeyMethod = SignerGrpc.getGenerateKeyMethod) == null) {
          SignerGrpc.getGenerateKeyMethod = getGenerateKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.GenerateKeyRequest, com.stakecraft.rutli.grpc.GenerateKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GenerateKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.GenerateKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.GenerateKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("GenerateKey"))
              .build();
        }
      }
    }
    return getGenerateKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PublicKeyRequest,
      com.stakecraft.rutli.grpc.PublicKeyReply> getPublicKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "PublicKey",
      requestType = com.stakecraft.rutli.grpc.PublicKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.PublicKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PublicKeyRequest,
      com.stakecraft.rutli.grpc.PublicKeyReply> getPublicKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PublicKeyRequest, com.stakecraft.rutli.grpc.PublicKeyReply> getPublicKeyMethod;
    if ((getPublicKeyMethod = SignerGrpc.getPublicKeyMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getPublicKeyMethod = SignerGrpc.getPublicKeyMethod) == null) {
          SignerGrpc.getPublicKeyMethod = getPublicKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.PublicKeyRequest, com.stakecraft.rutli.grpc.PublicKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "PublicKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.PublicKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.PublicKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("PublicKey"))
              .build();
        }
      }
    }
    return getPublicKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyInfoRequest,
      com.stakecraft.rutli.grpc.KeyInfoReply> getKeyInfoMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "KeyInfo",
      requestType = com.stakecraft.rutli.grpc.KeyInfoRequest.class,
      responseType = com.stakecraft.rutli.grpc.KeyInfoReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyInfoRequest,
      com.stakecraft.rutli.grpc.KeyInfoReply> getKeyInfoMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyInfoRequest, com.stakecraft.rutli.grpc.KeyInfoReply> getKeyInfoMethod;
    if ((getKeyInfoMethod = SignerGrpc.getKeyInfoMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getKeyInfoMethod = SignerGrpc.getKeyInfoMethod) == null) {
          SignerGrpc.getKeyInfoMethod = getKeyInfoMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.KeyInfoRequest, com.stakecraft.rutli.grpc.KeyInfoReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "KeyInfo"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyInfoRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyInfoReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("KeyInfo"))
              .build();
        }
      }
    }
    return getKeyInfoMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DeleteKeyRequest,
      com.stakecraft.rutli.grpc.DeleteKeyReply> getDeleteKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteKey",
      requestType = com.stakecraft.rutli.grpc.DeleteKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.DeleteKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DeleteKeyRequest,
      com.stakecraft.rutli.grpc.DeleteKeyReply> getDeleteKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DeleteKeyRequest, com.stakecraft.rutli.grpc.DeleteKeyReply> getDeleteKeyMethod;
    if ((getDeleteKeyMethod = SignerGrpc.getDeleteKeyMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getDeleteKeyMethod = SignerGrpc.getDeleteKeyMethod) == null) {
          SignerGrpc.getDeleteKeyMethod = getDeleteKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DeleteKeyRequest, com.stakecraft.rutli.grpc.DeleteKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DeleteKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DeleteKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("DeleteKey"))
              .build();
        }
      }
    }
    return getDeleteKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DecryptRequest,
      com.stakecraft.rutli.grpc.DecryptReply> getDecryptMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Decrypt",
      requestType = com.stakecraft.rutli.grpc.DecryptRequest.class,
      responseType = com.stakecraft.rutli.grpc.DecryptReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DecryptRequest,
      com.stakecraft.rutli.grpc.DecryptReply> getDecryptMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DecryptRequest, com.stakecraft.rutli.grpc.DecryptReply> getDecryptMethod;
    if ((getDecryptMethod = SignerGrpc.getDecryptMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getDecryptMethod = SignerGrpc.getDecryptMethod) == null) {
          SignerGrpc.getDecryptMethod = getDecryptMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DecryptRequest, com.stakecraft.rutli.grpc.DecryptReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Decrypt"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DecryptRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DecryptReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("Decrypt"))
              .build();
        }
      }
    }
    return getDecryptMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest,
      com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricEncryptMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "SymmetricEncrypt",
      requestType = com.stakecraft.rutli.grpc.SymmetricRequest.class,
      responseType = com.stakecraft.rutli.grpc.SymmetricReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest,
      com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricEncryptMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest, com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricEncryptMethod;
    if ((getSymmetricEncryptMethod = SignerGrpc.getSymmetricEncryptMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getSymmetricEncryptMethod = SignerGrpc.getSymmetricEncryptMethod) == null) {
          SignerGrpc.getSymmetricEncryptMethod = getSymmetricEncryptMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.SymmetricRequest, com.stakecraft.rutli.grpc.SymmetricReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "SymmetricEncrypt"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SymmetricRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SymmetricReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("SymmetricEncrypt"))
              .build();
        }
      }
    }
    return getSymmetricEncryptMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest,
      com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricDecryptMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "SymmetricDecrypt",
      requestType = com.stakecraft.rutli.grpc.SymmetricRequest.class,
      responseType = com.stakecraft.rutli.grpc.SymmetricReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest,
      com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricDecryptMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SymmetricRequest, com.stakecraft.rutli.grpc.SymmetricReply> getSymmetricDecryptMethod;
    if ((getSymmetricDecryptMethod = SignerGrpc.getSymmetricDecryptMethod) == null) {
      synchronized (SignerGrpc.class) {
        if ((getSymmetricDecryptMethod = SignerGrpc.getSymmetricDecryptMethod) == null) {
          SignerGrpc.getSymmetricDecryptMethod = getSymmetricDecryptMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.SymmetricRequest, com.stakecraft.rutli.grpc.SymmetricReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "SymmetricDecrypt"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SymmetricRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SymmetricReply.getDefaultInstance()))
              .setSchemaDescriptor(new SignerMethodDescriptorSupplier("SymmetricDecrypt"))
              .build();
        }
      }
    }
    return getSymmetricDecryptMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static SignerStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SignerStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SignerStub>() {
        @java.lang.Override
        public SignerStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SignerStub(channel, callOptions);
        }
      };
    return SignerStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports all types of calls on the service
   */
  public static SignerBlockingV2Stub newBlockingV2Stub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SignerBlockingV2Stub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SignerBlockingV2Stub>() {
        @java.lang.Override
        public SignerBlockingV2Stub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SignerBlockingV2Stub(channel, callOptions);
        }
      };
    return SignerBlockingV2Stub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static SignerBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SignerBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SignerBlockingStub>() {
        @java.lang.Override
        public SignerBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SignerBlockingStub(channel, callOptions);
        }
      };
    return SignerBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static SignerFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SignerFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SignerFutureStub>() {
        @java.lang.Override
        public SignerFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SignerFutureStub(channel, callOptions);
        }
      };
    return SignerFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public interface AsyncService {

    /**
     */
    default void health(com.stakecraft.rutli.grpc.HealthRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.HealthReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getHealthMethod(), responseObserver);
    }

    /**
     */
    default void groupKey(com.stakecraft.rutli.grpc.GroupKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GroupKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGroupKeyMethod(), responseObserver);
    }

    /**
     */
    default void dkg(com.stakecraft.rutli.grpc.DkgRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDkgMethod(), responseObserver);
    }

    /**
     */
    default void sign(com.stakecraft.rutli.grpc.SignRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getSignMethod(), responseObserver);
    }

    /**
     * <pre>
     * Proactively refresh the shares for a key. Same group key out; shares re-randomized cluster-wide.
     * </pre>
     */
    default void refresh(com.stakecraft.rutli.grpc.RefreshRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.RefreshReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRefreshMethod(), responseObserver);
    }

    /**
     * <pre>
     * This node's local, read-only view of one FROST key — public values only (group key, its own
     * verifying share, the public key package and its digest, provenance). For `rutli-cosigner
     * verify-key`, which asks every node and compares. Allowlisted like GroupKey. The driver does
     * not call it.
     * </pre>
     */
    default void keyStatus(com.stakecraft.rutli.grpc.KeyStatusRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyStatusReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getKeyStatusMethod(), responseObserver);
    }

    /**
     * <pre>
     * Split ceremony verification: sign a fixed, server-computed test digest for an imported key
     * with EXACTLY the given quorum, so every t-subset of cosigners can be proven to sign. The
     * message is never caller-supplied (0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
     * key_id), from the key's recorded provenance), and keys without a dealer-split origin are
     * refused. Callable by the operator role (operator_allowlist) as well as the driver role.
     * </pre>
     */
    default void ceremonySignTest(com.stakecraft.rutli.grpc.CeremonySignTestRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonySignTestReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonySignTestMethod(), responseObserver);
    }

    /**
     * <pre>
     * What this cluster supports. The driver queries it at startup instead of hardcoding specs, so
     * adding a key type later needs no driver release.
     * </pre>
     */
    default void capabilities(com.stakecraft.rutli.grpc.CapabilitiesRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CapabilitiesReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCapabilitiesMethod(), responseObserver);
    }

    /**
     * <pre>
     * Generate a hosted key. key_id is caller-supplied, making retries idempotent.
     * </pre>
     */
    default void generateKey(com.stakecraft.rutli.grpc.GenerateKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GenerateKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGenerateKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * X.509 SubjectPublicKeyInfo DER for an asymmetric hosted key.
     * </pre>
     */
    default void publicKey(com.stakecraft.rutli.grpc.PublicKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PublicKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getPublicKeyMethod(), responseObserver);
    }

    /**
     */
    default void keyInfo(com.stakecraft.rutli.grpc.KeyInfoRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyInfoReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getKeyInfoMethod(), responseObserver);
    }

    /**
     */
    default void deleteKey(com.stakecraft.rutli.grpc.DeleteKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DeleteKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * RSAES-OAEP-SHA256. The full unpad happens server-side — returning raw c^d mod N would be a
     * padding oracle.
     * </pre>
     */
    default void decrypt(com.stakecraft.rutli.grpc.DecryptRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DecryptReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDecryptMethod(), responseObserver);
    }

    /**
     */
    default void symmetricEncrypt(com.stakecraft.rutli.grpc.SymmetricRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getSymmetricEncryptMethod(), responseObserver);
    }

    /**
     */
    default void symmetricDecrypt(com.stakecraft.rutli.grpc.SymmetricRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getSymmetricDecryptMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service Signer.
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public static abstract class SignerImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return SignerGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service Signer.
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public static final class SignerStub
      extends io.grpc.stub.AbstractAsyncStub<SignerStub> {
    private SignerStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SignerStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SignerStub(channel, callOptions);
    }

    /**
     */
    public void health(com.stakecraft.rutli.grpc.HealthRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.HealthReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getHealthMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void groupKey(com.stakecraft.rutli.grpc.GroupKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GroupKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGroupKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void dkg(com.stakecraft.rutli.grpc.DkgRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDkgMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void sign(com.stakecraft.rutli.grpc.SignRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getSignMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Proactively refresh the shares for a key. Same group key out; shares re-randomized cluster-wide.
     * </pre>
     */
    public void refresh(com.stakecraft.rutli.grpc.RefreshRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.RefreshReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRefreshMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * This node's local, read-only view of one FROST key — public values only (group key, its own
     * verifying share, the public key package and its digest, provenance). For `rutli-cosigner
     * verify-key`, which asks every node and compares. Allowlisted like GroupKey. The driver does
     * not call it.
     * </pre>
     */
    public void keyStatus(com.stakecraft.rutli.grpc.KeyStatusRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyStatusReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getKeyStatusMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Split ceremony verification: sign a fixed, server-computed test digest for an imported key
     * with EXACTLY the given quorum, so every t-subset of cosigners can be proven to sign. The
     * message is never caller-supplied (0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
     * key_id), from the key's recorded provenance), and keys without a dealer-split origin are
     * refused. Callable by the operator role (operator_allowlist) as well as the driver role.
     * </pre>
     */
    public void ceremonySignTest(com.stakecraft.rutli.grpc.CeremonySignTestRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonySignTestReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonySignTestMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * What this cluster supports. The driver queries it at startup instead of hardcoding specs, so
     * adding a key type later needs no driver release.
     * </pre>
     */
    public void capabilities(com.stakecraft.rutli.grpc.CapabilitiesRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CapabilitiesReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCapabilitiesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Generate a hosted key. key_id is caller-supplied, making retries idempotent.
     * </pre>
     */
    public void generateKey(com.stakecraft.rutli.grpc.GenerateKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GenerateKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGenerateKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * X.509 SubjectPublicKeyInfo DER for an asymmetric hosted key.
     * </pre>
     */
    public void publicKey(com.stakecraft.rutli.grpc.PublicKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PublicKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getPublicKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void keyInfo(com.stakecraft.rutli.grpc.KeyInfoRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyInfoReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getKeyInfoMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteKey(com.stakecraft.rutli.grpc.DeleteKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DeleteKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * RSAES-OAEP-SHA256. The full unpad happens server-side — returning raw c^d mod N would be a
     * padding oracle.
     * </pre>
     */
    public void decrypt(com.stakecraft.rutli.grpc.DecryptRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DecryptReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDecryptMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void symmetricEncrypt(com.stakecraft.rutli.grpc.SymmetricRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getSymmetricEncryptMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void symmetricDecrypt(com.stakecraft.rutli.grpc.SymmetricRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getSymmetricDecryptMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service Signer.
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public static final class SignerBlockingV2Stub
      extends io.grpc.stub.AbstractBlockingStub<SignerBlockingV2Stub> {
    private SignerBlockingV2Stub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SignerBlockingV2Stub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SignerBlockingV2Stub(channel, callOptions);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.HealthReply health(com.stakecraft.rutli.grpc.HealthRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getHealthMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.GroupKeyReply groupKey(com.stakecraft.rutli.grpc.GroupKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getGroupKeyMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgReply dkg(com.stakecraft.rutli.grpc.DkgRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDkgMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignReply sign(com.stakecraft.rutli.grpc.SignRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getSignMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Proactively refresh the shares for a key. Same group key out; shares re-randomized cluster-wide.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.RefreshReply refresh(com.stakecraft.rutli.grpc.RefreshRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getRefreshMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's local, read-only view of one FROST key — public values only (group key, its own
     * verifying share, the public key package and its digest, provenance). For `rutli-cosigner
     * verify-key`, which asks every node and compares. Allowlisted like GroupKey. The driver does
     * not call it.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.KeyStatusReply keyStatus(com.stakecraft.rutli.grpc.KeyStatusRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getKeyStatusMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Split ceremony verification: sign a fixed, server-computed test digest for an imported key
     * with EXACTLY the given quorum, so every t-subset of cosigners can be proven to sign. The
     * message is never caller-supplied (0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
     * key_id), from the key's recorded provenance), and keys without a dealer-split origin are
     * refused. Callable by the operator role (operator_allowlist) as well as the driver role.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonySignTestReply ceremonySignTest(com.stakecraft.rutli.grpc.CeremonySignTestRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonySignTestMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * What this cluster supports. The driver queries it at startup instead of hardcoding specs, so
     * adding a key type later needs no driver release.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CapabilitiesReply capabilities(com.stakecraft.rutli.grpc.CapabilitiesRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCapabilitiesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Generate a hosted key. key_id is caller-supplied, making retries idempotent.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.GenerateKeyReply generateKey(com.stakecraft.rutli.grpc.GenerateKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getGenerateKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * X.509 SubjectPublicKeyInfo DER for an asymmetric hosted key.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.PublicKeyReply publicKey(com.stakecraft.rutli.grpc.PublicKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getPublicKeyMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.KeyInfoReply keyInfo(com.stakecraft.rutli.grpc.KeyInfoRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getKeyInfoMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DeleteKeyReply deleteKey(com.stakecraft.rutli.grpc.DeleteKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDeleteKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * RSAES-OAEP-SHA256. The full unpad happens server-side — returning raw c^d mod N would be a
     * padding oracle.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.DecryptReply decrypt(com.stakecraft.rutli.grpc.DecryptRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDecryptMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SymmetricReply symmetricEncrypt(com.stakecraft.rutli.grpc.SymmetricRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getSymmetricEncryptMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SymmetricReply symmetricDecrypt(com.stakecraft.rutli.grpc.SymmetricRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getSymmetricDecryptMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do limited synchronous rpc calls to service Signer.
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public static final class SignerBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<SignerBlockingStub> {
    private SignerBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SignerBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SignerBlockingStub(channel, callOptions);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.HealthReply health(com.stakecraft.rutli.grpc.HealthRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getHealthMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.GroupKeyReply groupKey(com.stakecraft.rutli.grpc.GroupKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGroupKeyMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgReply dkg(com.stakecraft.rutli.grpc.DkgRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDkgMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignReply sign(com.stakecraft.rutli.grpc.SignRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getSignMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Proactively refresh the shares for a key. Same group key out; shares re-randomized cluster-wide.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.RefreshReply refresh(com.stakecraft.rutli.grpc.RefreshRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRefreshMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's local, read-only view of one FROST key — public values only (group key, its own
     * verifying share, the public key package and its digest, provenance). For `rutli-cosigner
     * verify-key`, which asks every node and compares. Allowlisted like GroupKey. The driver does
     * not call it.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.KeyStatusReply keyStatus(com.stakecraft.rutli.grpc.KeyStatusRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getKeyStatusMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Split ceremony verification: sign a fixed, server-computed test digest for an imported key
     * with EXACTLY the given quorum, so every t-subset of cosigners can be proven to sign. The
     * message is never caller-supplied (0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
     * key_id), from the key's recorded provenance), and keys without a dealer-split origin are
     * refused. Callable by the operator role (operator_allowlist) as well as the driver role.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonySignTestReply ceremonySignTest(com.stakecraft.rutli.grpc.CeremonySignTestRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonySignTestMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * What this cluster supports. The driver queries it at startup instead of hardcoding specs, so
     * adding a key type later needs no driver release.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CapabilitiesReply capabilities(com.stakecraft.rutli.grpc.CapabilitiesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCapabilitiesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Generate a hosted key. key_id is caller-supplied, making retries idempotent.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.GenerateKeyReply generateKey(com.stakecraft.rutli.grpc.GenerateKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGenerateKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * X.509 SubjectPublicKeyInfo DER for an asymmetric hosted key.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.PublicKeyReply publicKey(com.stakecraft.rutli.grpc.PublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getPublicKeyMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.KeyInfoReply keyInfo(com.stakecraft.rutli.grpc.KeyInfoRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getKeyInfoMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DeleteKeyReply deleteKey(com.stakecraft.rutli.grpc.DeleteKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * RSAES-OAEP-SHA256. The full unpad happens server-side — returning raw c^d mod N would be a
     * padding oracle.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.DecryptReply decrypt(com.stakecraft.rutli.grpc.DecryptRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDecryptMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SymmetricReply symmetricEncrypt(com.stakecraft.rutli.grpc.SymmetricRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getSymmetricEncryptMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SymmetricReply symmetricDecrypt(com.stakecraft.rutli.grpc.SymmetricRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getSymmetricDecryptMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service Signer.
   * <pre>
   * Client-facing signing API. This is what the Scala FrostBackend (the Canton KMS driver's MPC
   * backend) calls. The node it connects to acts as the session leader for that request.
   * </pre>
   */
  public static final class SignerFutureStub
      extends io.grpc.stub.AbstractFutureStub<SignerFutureStub> {
    private SignerFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SignerFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SignerFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.HealthReply> health(
        com.stakecraft.rutli.grpc.HealthRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getHealthMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.GroupKeyReply> groupKey(
        com.stakecraft.rutli.grpc.GroupKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGroupKeyMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgReply> dkg(
        com.stakecraft.rutli.grpc.DkgRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDkgMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.SignReply> sign(
        com.stakecraft.rutli.grpc.SignRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getSignMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Proactively refresh the shares for a key. Same group key out; shares re-randomized cluster-wide.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.RefreshReply> refresh(
        com.stakecraft.rutli.grpc.RefreshRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRefreshMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * This node's local, read-only view of one FROST key — public values only (group key, its own
     * verifying share, the public key package and its digest, provenance). For `rutli-cosigner
     * verify-key`, which asks every node and compares. Allowlisted like GroupKey. The driver does
     * not call it.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.KeyStatusReply> keyStatus(
        com.stakecraft.rutli.grpc.KeyStatusRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getKeyStatusMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Split ceremony verification: sign a fixed, server-computed test digest for an imported key
     * with EXACTLY the given quorum, so every t-subset of cosigners can be proven to sign. The
     * message is never caller-supplied (0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
     * key_id), from the key's recorded provenance), and keys without a dealer-split origin are
     * refused. Callable by the operator role (operator_allowlist) as well as the driver role.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonySignTestReply> ceremonySignTest(
        com.stakecraft.rutli.grpc.CeremonySignTestRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonySignTestMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * What this cluster supports. The driver queries it at startup instead of hardcoding specs, so
     * adding a key type later needs no driver release.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CapabilitiesReply> capabilities(
        com.stakecraft.rutli.grpc.CapabilitiesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCapabilitiesMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Generate a hosted key. key_id is caller-supplied, making retries idempotent.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.GenerateKeyReply> generateKey(
        com.stakecraft.rutli.grpc.GenerateKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGenerateKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * X.509 SubjectPublicKeyInfo DER for an asymmetric hosted key.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.PublicKeyReply> publicKey(
        com.stakecraft.rutli.grpc.PublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getPublicKeyMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.KeyInfoReply> keyInfo(
        com.stakecraft.rutli.grpc.KeyInfoRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getKeyInfoMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DeleteKeyReply> deleteKey(
        com.stakecraft.rutli.grpc.DeleteKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * RSAES-OAEP-SHA256. The full unpad happens server-side — returning raw c^d mod N would be a
     * padding oracle.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DecryptReply> decrypt(
        com.stakecraft.rutli.grpc.DecryptRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDecryptMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.SymmetricReply> symmetricEncrypt(
        com.stakecraft.rutli.grpc.SymmetricRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getSymmetricEncryptMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.SymmetricReply> symmetricDecrypt(
        com.stakecraft.rutli.grpc.SymmetricRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getSymmetricDecryptMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_HEALTH = 0;
  private static final int METHODID_GROUP_KEY = 1;
  private static final int METHODID_DKG = 2;
  private static final int METHODID_SIGN = 3;
  private static final int METHODID_REFRESH = 4;
  private static final int METHODID_KEY_STATUS = 5;
  private static final int METHODID_CEREMONY_SIGN_TEST = 6;
  private static final int METHODID_CAPABILITIES = 7;
  private static final int METHODID_GENERATE_KEY = 8;
  private static final int METHODID_PUBLIC_KEY = 9;
  private static final int METHODID_KEY_INFO = 10;
  private static final int METHODID_DELETE_KEY = 11;
  private static final int METHODID_DECRYPT = 12;
  private static final int METHODID_SYMMETRIC_ENCRYPT = 13;
  private static final int METHODID_SYMMETRIC_DECRYPT = 14;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final AsyncService serviceImpl;
    private final int methodId;

    MethodHandlers(AsyncService serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_HEALTH:
          serviceImpl.health((com.stakecraft.rutli.grpc.HealthRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.HealthReply>) responseObserver);
          break;
        case METHODID_GROUP_KEY:
          serviceImpl.groupKey((com.stakecraft.rutli.grpc.GroupKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GroupKeyReply>) responseObserver);
          break;
        case METHODID_DKG:
          serviceImpl.dkg((com.stakecraft.rutli.grpc.DkgRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgReply>) responseObserver);
          break;
        case METHODID_SIGN:
          serviceImpl.sign((com.stakecraft.rutli.grpc.SignRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignReply>) responseObserver);
          break;
        case METHODID_REFRESH:
          serviceImpl.refresh((com.stakecraft.rutli.grpc.RefreshRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.RefreshReply>) responseObserver);
          break;
        case METHODID_KEY_STATUS:
          serviceImpl.keyStatus((com.stakecraft.rutli.grpc.KeyStatusRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyStatusReply>) responseObserver);
          break;
        case METHODID_CEREMONY_SIGN_TEST:
          serviceImpl.ceremonySignTest((com.stakecraft.rutli.grpc.CeremonySignTestRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonySignTestReply>) responseObserver);
          break;
        case METHODID_CAPABILITIES:
          serviceImpl.capabilities((com.stakecraft.rutli.grpc.CapabilitiesRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CapabilitiesReply>) responseObserver);
          break;
        case METHODID_GENERATE_KEY:
          serviceImpl.generateKey((com.stakecraft.rutli.grpc.GenerateKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.GenerateKeyReply>) responseObserver);
          break;
        case METHODID_PUBLIC_KEY:
          serviceImpl.publicKey((com.stakecraft.rutli.grpc.PublicKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PublicKeyReply>) responseObserver);
          break;
        case METHODID_KEY_INFO:
          serviceImpl.keyInfo((com.stakecraft.rutli.grpc.KeyInfoRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyInfoReply>) responseObserver);
          break;
        case METHODID_DELETE_KEY:
          serviceImpl.deleteKey((com.stakecraft.rutli.grpc.DeleteKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DeleteKeyReply>) responseObserver);
          break;
        case METHODID_DECRYPT:
          serviceImpl.decrypt((com.stakecraft.rutli.grpc.DecryptRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DecryptReply>) responseObserver);
          break;
        case METHODID_SYMMETRIC_ENCRYPT:
          serviceImpl.symmetricEncrypt((com.stakecraft.rutli.grpc.SymmetricRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply>) responseObserver);
          break;
        case METHODID_SYMMETRIC_DECRYPT:
          serviceImpl.symmetricDecrypt((com.stakecraft.rutli.grpc.SymmetricRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SymmetricReply>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  public static final io.grpc.ServerServiceDefinition bindService(AsyncService service) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          getHealthMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.HealthRequest,
              com.stakecraft.rutli.grpc.HealthReply>(
                service, METHODID_HEALTH)))
        .addMethod(
          getGroupKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.GroupKeyRequest,
              com.stakecraft.rutli.grpc.GroupKeyReply>(
                service, METHODID_GROUP_KEY)))
        .addMethod(
          getDkgMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgRequest,
              com.stakecraft.rutli.grpc.DkgReply>(
                service, METHODID_DKG)))
        .addMethod(
          getSignMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.SignRequest,
              com.stakecraft.rutli.grpc.SignReply>(
                service, METHODID_SIGN)))
        .addMethod(
          getRefreshMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.RefreshRequest,
              com.stakecraft.rutli.grpc.RefreshReply>(
                service, METHODID_REFRESH)))
        .addMethod(
          getKeyStatusMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.KeyStatusRequest,
              com.stakecraft.rutli.grpc.KeyStatusReply>(
                service, METHODID_KEY_STATUS)))
        .addMethod(
          getCeremonySignTestMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonySignTestRequest,
              com.stakecraft.rutli.grpc.CeremonySignTestReply>(
                service, METHODID_CEREMONY_SIGN_TEST)))
        .addMethod(
          getCapabilitiesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CapabilitiesRequest,
              com.stakecraft.rutli.grpc.CapabilitiesReply>(
                service, METHODID_CAPABILITIES)))
        .addMethod(
          getGenerateKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.GenerateKeyRequest,
              com.stakecraft.rutli.grpc.GenerateKeyReply>(
                service, METHODID_GENERATE_KEY)))
        .addMethod(
          getPublicKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.PublicKeyRequest,
              com.stakecraft.rutli.grpc.PublicKeyReply>(
                service, METHODID_PUBLIC_KEY)))
        .addMethod(
          getKeyInfoMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.KeyInfoRequest,
              com.stakecraft.rutli.grpc.KeyInfoReply>(
                service, METHODID_KEY_INFO)))
        .addMethod(
          getDeleteKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DeleteKeyRequest,
              com.stakecraft.rutli.grpc.DeleteKeyReply>(
                service, METHODID_DELETE_KEY)))
        .addMethod(
          getDecryptMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DecryptRequest,
              com.stakecraft.rutli.grpc.DecryptReply>(
                service, METHODID_DECRYPT)))
        .addMethod(
          getSymmetricEncryptMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.SymmetricRequest,
              com.stakecraft.rutli.grpc.SymmetricReply>(
                service, METHODID_SYMMETRIC_ENCRYPT)))
        .addMethod(
          getSymmetricDecryptMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.SymmetricRequest,
              com.stakecraft.rutli.grpc.SymmetricReply>(
                service, METHODID_SYMMETRIC_DECRYPT)))
        .build();
  }

  private static abstract class SignerBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    SignerBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.stakecraft.rutli.grpc.CosignerProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("Signer");
    }
  }

  private static final class SignerFileDescriptorSupplier
      extends SignerBaseDescriptorSupplier {
    SignerFileDescriptorSupplier() {}
  }

  private static final class SignerMethodDescriptorSupplier
      extends SignerBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    SignerMethodDescriptorSupplier(java.lang.String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (SignerGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new SignerFileDescriptorSupplier())
              .addMethod(getHealthMethod())
              .addMethod(getGroupKeyMethod())
              .addMethod(getDkgMethod())
              .addMethod(getSignMethod())
              .addMethod(getRefreshMethod())
              .addMethod(getKeyStatusMethod())
              .addMethod(getCeremonySignTestMethod())
              .addMethod(getCapabilitiesMethod())
              .addMethod(getGenerateKeyMethod())
              .addMethod(getPublicKeyMethod())
              .addMethod(getKeyInfoMethod())
              .addMethod(getDeleteKeyMethod())
              .addMethod(getDecryptMethod())
              .addMethod(getSymmetricEncryptMethod())
              .addMethod(getSymmetricDecryptMethod())
              .build();
        }
      }
    }
    return result;
  }
}
