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
  }

  private static final int METHODID_HEALTH = 0;
  private static final int METHODID_GROUP_KEY = 1;
  private static final int METHODID_DKG = 2;
  private static final int METHODID_SIGN = 3;

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
              .build();
        }
      }
    }
    return result;
  }
}
