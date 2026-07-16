package com.stakecraft.rutli.grpc;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
 * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
 * </pre>
 */
@io.grpc.stub.annotations.GrpcGenerated
public final class PeerGrpc {

  private PeerGrpc() {}

  public static final java.lang.String SERVICE_NAME = "rutli.cosigner.v1.Peer";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound1Request,
      com.stakecraft.rutli.grpc.SignRound1Reply> getSignRound1Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "SignRound1",
      requestType = com.stakecraft.rutli.grpc.SignRound1Request.class,
      responseType = com.stakecraft.rutli.grpc.SignRound1Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound1Request,
      com.stakecraft.rutli.grpc.SignRound1Reply> getSignRound1Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound1Request, com.stakecraft.rutli.grpc.SignRound1Reply> getSignRound1Method;
    if ((getSignRound1Method = PeerGrpc.getSignRound1Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getSignRound1Method = PeerGrpc.getSignRound1Method) == null) {
          PeerGrpc.getSignRound1Method = getSignRound1Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.SignRound1Request, com.stakecraft.rutli.grpc.SignRound1Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "SignRound1"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignRound1Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignRound1Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("SignRound1"))
              .build();
        }
      }
    }
    return getSignRound1Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound2Request,
      com.stakecraft.rutli.grpc.SignRound2Reply> getSignRound2Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "SignRound2",
      requestType = com.stakecraft.rutli.grpc.SignRound2Request.class,
      responseType = com.stakecraft.rutli.grpc.SignRound2Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound2Request,
      com.stakecraft.rutli.grpc.SignRound2Reply> getSignRound2Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.SignRound2Request, com.stakecraft.rutli.grpc.SignRound2Reply> getSignRound2Method;
    if ((getSignRound2Method = PeerGrpc.getSignRound2Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getSignRound2Method = PeerGrpc.getSignRound2Method) == null) {
          PeerGrpc.getSignRound2Method = getSignRound2Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.SignRound2Request, com.stakecraft.rutli.grpc.SignRound2Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "SignRound2"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignRound2Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.SignRound2Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("SignRound2"))
              .build();
        }
      }
    }
    return getSignRound2Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart1Request,
      com.stakecraft.rutli.grpc.DkgPart1Reply> getDkgPart1Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DkgPart1",
      requestType = com.stakecraft.rutli.grpc.DkgPart1Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart1Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart1Request,
      com.stakecraft.rutli.grpc.DkgPart1Reply> getDkgPart1Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart1Request, com.stakecraft.rutli.grpc.DkgPart1Reply> getDkgPart1Method;
    if ((getDkgPart1Method = PeerGrpc.getDkgPart1Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getDkgPart1Method = PeerGrpc.getDkgPart1Method) == null) {
          PeerGrpc.getDkgPart1Method = getDkgPart1Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgPart1Request, com.stakecraft.rutli.grpc.DkgPart1Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DkgPart1"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart1Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart1Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("DkgPart1"))
              .build();
        }
      }
    }
    return getDkgPart1Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request,
      com.stakecraft.rutli.grpc.DkgPart2Reply> getDkgPart2Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DkgPart2",
      requestType = com.stakecraft.rutli.grpc.DkgPart2Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart2Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request,
      com.stakecraft.rutli.grpc.DkgPart2Reply> getDkgPart2Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request, com.stakecraft.rutli.grpc.DkgPart2Reply> getDkgPart2Method;
    if ((getDkgPart2Method = PeerGrpc.getDkgPart2Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getDkgPart2Method = PeerGrpc.getDkgPart2Method) == null) {
          PeerGrpc.getDkgPart2Method = getDkgPart2Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgPart2Request, com.stakecraft.rutli.grpc.DkgPart2Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DkgPart2"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart2Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart2Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("DkgPart2"))
              .build();
        }
      }
    }
    return getDkgPart2Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request,
      com.stakecraft.rutli.grpc.DkgPart3Reply> getDkgPart3Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DkgPart3",
      requestType = com.stakecraft.rutli.grpc.DkgPart3Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart3Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request,
      com.stakecraft.rutli.grpc.DkgPart3Reply> getDkgPart3Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request, com.stakecraft.rutli.grpc.DkgPart3Reply> getDkgPart3Method;
    if ((getDkgPart3Method = PeerGrpc.getDkgPart3Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getDkgPart3Method = PeerGrpc.getDkgPart3Method) == null) {
          PeerGrpc.getDkgPart3Method = getDkgPart3Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgPart3Request, com.stakecraft.rutli.grpc.DkgPart3Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DkgPart3"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart3Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart3Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("DkgPart3"))
              .build();
        }
      }
    }
    return getDkgPart3Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshPart1Request,
      com.stakecraft.rutli.grpc.DkgPart1Reply> getRefreshPart1Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RefreshPart1",
      requestType = com.stakecraft.rutli.grpc.RefreshPart1Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart1Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshPart1Request,
      com.stakecraft.rutli.grpc.DkgPart1Reply> getRefreshPart1Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.RefreshPart1Request, com.stakecraft.rutli.grpc.DkgPart1Reply> getRefreshPart1Method;
    if ((getRefreshPart1Method = PeerGrpc.getRefreshPart1Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getRefreshPart1Method = PeerGrpc.getRefreshPart1Method) == null) {
          PeerGrpc.getRefreshPart1Method = getRefreshPart1Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.RefreshPart1Request, com.stakecraft.rutli.grpc.DkgPart1Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RefreshPart1"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.RefreshPart1Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart1Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("RefreshPart1"))
              .build();
        }
      }
    }
    return getRefreshPart1Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request,
      com.stakecraft.rutli.grpc.DkgPart2Reply> getRefreshPart2Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RefreshPart2",
      requestType = com.stakecraft.rutli.grpc.DkgPart2Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart2Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request,
      com.stakecraft.rutli.grpc.DkgPart2Reply> getRefreshPart2Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart2Request, com.stakecraft.rutli.grpc.DkgPart2Reply> getRefreshPart2Method;
    if ((getRefreshPart2Method = PeerGrpc.getRefreshPart2Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getRefreshPart2Method = PeerGrpc.getRefreshPart2Method) == null) {
          PeerGrpc.getRefreshPart2Method = getRefreshPart2Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgPart2Request, com.stakecraft.rutli.grpc.DkgPart2Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RefreshPart2"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart2Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart2Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("RefreshPart2"))
              .build();
        }
      }
    }
    return getRefreshPart2Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request,
      com.stakecraft.rutli.grpc.DkgPart3Reply> getRefreshPart3Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RefreshPart3",
      requestType = com.stakecraft.rutli.grpc.DkgPart3Request.class,
      responseType = com.stakecraft.rutli.grpc.DkgPart3Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request,
      com.stakecraft.rutli.grpc.DkgPart3Reply> getRefreshPart3Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.DkgPart3Request, com.stakecraft.rutli.grpc.DkgPart3Reply> getRefreshPart3Method;
    if ((getRefreshPart3Method = PeerGrpc.getRefreshPart3Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getRefreshPart3Method = PeerGrpc.getRefreshPart3Method) == null) {
          PeerGrpc.getRefreshPart3Method = getRefreshPart3Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.DkgPart3Request, com.stakecraft.rutli.grpc.DkgPart3Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RefreshPart3"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart3Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.DkgPart3Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("RefreshPart3"))
              .build();
        }
      }
    }
    return getRefreshPart3Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.AbortSignRequest,
      com.stakecraft.rutli.grpc.AbortSignReply> getAbortSignMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "AbortSign",
      requestType = com.stakecraft.rutli.grpc.AbortSignRequest.class,
      responseType = com.stakecraft.rutli.grpc.AbortSignReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.AbortSignRequest,
      com.stakecraft.rutli.grpc.AbortSignReply> getAbortSignMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.AbortSignRequest, com.stakecraft.rutli.grpc.AbortSignReply> getAbortSignMethod;
    if ((getAbortSignMethod = PeerGrpc.getAbortSignMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getAbortSignMethod = PeerGrpc.getAbortSignMethod) == null) {
          PeerGrpc.getAbortSignMethod = getAbortSignMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.AbortSignRequest, com.stakecraft.rutli.grpc.AbortSignReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "AbortSign"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.AbortSignRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.AbortSignReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("AbortSign"))
              .build();
        }
      }
    }
    return getAbortSignMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static PeerStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<PeerStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<PeerStub>() {
        @java.lang.Override
        public PeerStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new PeerStub(channel, callOptions);
        }
      };
    return PeerStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports all types of calls on the service
   */
  public static PeerBlockingV2Stub newBlockingV2Stub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<PeerBlockingV2Stub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<PeerBlockingV2Stub>() {
        @java.lang.Override
        public PeerBlockingV2Stub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new PeerBlockingV2Stub(channel, callOptions);
        }
      };
    return PeerBlockingV2Stub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static PeerBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<PeerBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<PeerBlockingStub>() {
        @java.lang.Override
        public PeerBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new PeerBlockingStub(channel, callOptions);
        }
      };
    return PeerBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static PeerFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<PeerFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<PeerFutureStub>() {
        @java.lang.Override
        public PeerFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new PeerFutureStub(channel, callOptions);
        }
      };
    return PeerFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public interface AsyncService {

    /**
     */
    default void signRound1(com.stakecraft.rutli.grpc.SignRound1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound1Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getSignRound1Method(), responseObserver);
    }

    /**
     */
    default void signRound2(com.stakecraft.rutli.grpc.SignRound2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound2Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getSignRound2Method(), responseObserver);
    }

    /**
     */
    default void dkgPart1(com.stakecraft.rutli.grpc.DkgPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDkgPart1Method(), responseObserver);
    }

    /**
     */
    default void dkgPart2(com.stakecraft.rutli.grpc.DkgPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDkgPart2Method(), responseObserver);
    }

    /**
     */
    default void dkgPart3(com.stakecraft.rutli.grpc.DkgPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDkgPart3Method(), responseObserver);
    }

    /**
     */
    default void refreshPart1(com.stakecraft.rutli.grpc.RefreshPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRefreshPart1Method(), responseObserver);
    }

    /**
     */
    default void refreshPart2(com.stakecraft.rutli.grpc.DkgPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRefreshPart2Method(), responseObserver);
    }

    /**
     */
    default void refreshPart3(com.stakecraft.rutli.grpc.DkgPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRefreshPart3Method(), responseObserver);
    }

    /**
     * <pre>
     * Best-effort: drop an in-flight sign session so its round-1 nonces are freed immediately
     * instead of lingering until the pending-TTL sweep. Sent by the leader when a sign gives up.
     * </pre>
     */
    default void abortSign(com.stakecraft.rutli.grpc.AbortSignRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.AbortSignReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getAbortSignMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service Peer.
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public static abstract class PeerImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return PeerGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service Peer.
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public static final class PeerStub
      extends io.grpc.stub.AbstractAsyncStub<PeerStub> {
    private PeerStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected PeerStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new PeerStub(channel, callOptions);
    }

    /**
     */
    public void signRound1(com.stakecraft.rutli.grpc.SignRound1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound1Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getSignRound1Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void signRound2(com.stakecraft.rutli.grpc.SignRound2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound2Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getSignRound2Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void dkgPart1(com.stakecraft.rutli.grpc.DkgPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDkgPart1Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void dkgPart2(com.stakecraft.rutli.grpc.DkgPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDkgPart2Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void dkgPart3(com.stakecraft.rutli.grpc.DkgPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDkgPart3Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void refreshPart1(com.stakecraft.rutli.grpc.RefreshPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRefreshPart1Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void refreshPart2(com.stakecraft.rutli.grpc.DkgPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRefreshPart2Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void refreshPart3(com.stakecraft.rutli.grpc.DkgPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRefreshPart3Method(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Best-effort: drop an in-flight sign session so its round-1 nonces are freed immediately
     * instead of lingering until the pending-TTL sweep. Sent by the leader when a sign gives up.
     * </pre>
     */
    public void abortSign(com.stakecraft.rutli.grpc.AbortSignRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.AbortSignReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getAbortSignMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service Peer.
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public static final class PeerBlockingV2Stub
      extends io.grpc.stub.AbstractBlockingStub<PeerBlockingV2Stub> {
    private PeerBlockingV2Stub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected PeerBlockingV2Stub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new PeerBlockingV2Stub(channel, callOptions);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignRound1Reply signRound1(com.stakecraft.rutli.grpc.SignRound1Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getSignRound1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignRound2Reply signRound2(com.stakecraft.rutli.grpc.SignRound2Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getSignRound2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart1Reply dkgPart1(com.stakecraft.rutli.grpc.DkgPart1Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDkgPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart2Reply dkgPart2(com.stakecraft.rutli.grpc.DkgPart2Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDkgPart2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart3Reply dkgPart3(com.stakecraft.rutli.grpc.DkgPart3Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getDkgPart3Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart1Reply refreshPart1(com.stakecraft.rutli.grpc.RefreshPart1Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getRefreshPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart2Reply refreshPart2(com.stakecraft.rutli.grpc.DkgPart2Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getRefreshPart2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart3Reply refreshPart3(com.stakecraft.rutli.grpc.DkgPart3Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getRefreshPart3Method(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Best-effort: drop an in-flight sign session so its round-1 nonces are freed immediately
     * instead of lingering until the pending-TTL sweep. Sent by the leader when a sign gives up.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.AbortSignReply abortSign(com.stakecraft.rutli.grpc.AbortSignRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getAbortSignMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do limited synchronous rpc calls to service Peer.
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public static final class PeerBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<PeerBlockingStub> {
    private PeerBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected PeerBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new PeerBlockingStub(channel, callOptions);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignRound1Reply signRound1(com.stakecraft.rutli.grpc.SignRound1Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getSignRound1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.SignRound2Reply signRound2(com.stakecraft.rutli.grpc.SignRound2Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getSignRound2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart1Reply dkgPart1(com.stakecraft.rutli.grpc.DkgPart1Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDkgPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart2Reply dkgPart2(com.stakecraft.rutli.grpc.DkgPart2Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDkgPart2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart3Reply dkgPart3(com.stakecraft.rutli.grpc.DkgPart3Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDkgPart3Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart1Reply refreshPart1(com.stakecraft.rutli.grpc.RefreshPart1Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRefreshPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart2Reply refreshPart2(com.stakecraft.rutli.grpc.DkgPart2Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRefreshPart2Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.DkgPart3Reply refreshPart3(com.stakecraft.rutli.grpc.DkgPart3Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRefreshPart3Method(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Best-effort: drop an in-flight sign session so its round-1 nonces are freed immediately
     * instead of lingering until the pending-TTL sweep. Sent by the leader when a sign gives up.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.AbortSignReply abortSign(com.stakecraft.rutli.grpc.AbortSignRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getAbortSignMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service Peer.
   * <pre>
   * Mesh-internal API: cosigner-to-cosigner. All FROST packages are carried as opaque bytes
   * (serde_json of the frost-ed25519 types) so the protocol schema is not pinned into protobuf.
   * </pre>
   */
  public static final class PeerFutureStub
      extends io.grpc.stub.AbstractFutureStub<PeerFutureStub> {
    private PeerFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected PeerFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new PeerFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.SignRound1Reply> signRound1(
        com.stakecraft.rutli.grpc.SignRound1Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getSignRound1Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.SignRound2Reply> signRound2(
        com.stakecraft.rutli.grpc.SignRound2Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getSignRound2Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart1Reply> dkgPart1(
        com.stakecraft.rutli.grpc.DkgPart1Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDkgPart1Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart2Reply> dkgPart2(
        com.stakecraft.rutli.grpc.DkgPart2Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDkgPart2Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart3Reply> dkgPart3(
        com.stakecraft.rutli.grpc.DkgPart3Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDkgPart3Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart1Reply> refreshPart1(
        com.stakecraft.rutli.grpc.RefreshPart1Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRefreshPart1Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart2Reply> refreshPart2(
        com.stakecraft.rutli.grpc.DkgPart2Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRefreshPart2Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.DkgPart3Reply> refreshPart3(
        com.stakecraft.rutli.grpc.DkgPart3Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRefreshPart3Method(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Best-effort: drop an in-flight sign session so its round-1 nonces are freed immediately
     * instead of lingering until the pending-TTL sweep. Sent by the leader when a sign gives up.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.AbortSignReply> abortSign(
        com.stakecraft.rutli.grpc.AbortSignRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getAbortSignMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_SIGN_ROUND1 = 0;
  private static final int METHODID_SIGN_ROUND2 = 1;
  private static final int METHODID_DKG_PART1 = 2;
  private static final int METHODID_DKG_PART2 = 3;
  private static final int METHODID_DKG_PART3 = 4;
  private static final int METHODID_REFRESH_PART1 = 5;
  private static final int METHODID_REFRESH_PART2 = 6;
  private static final int METHODID_REFRESH_PART3 = 7;
  private static final int METHODID_ABORT_SIGN = 8;

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
        case METHODID_SIGN_ROUND1:
          serviceImpl.signRound1((com.stakecraft.rutli.grpc.SignRound1Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound1Reply>) responseObserver);
          break;
        case METHODID_SIGN_ROUND2:
          serviceImpl.signRound2((com.stakecraft.rutli.grpc.SignRound2Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.SignRound2Reply>) responseObserver);
          break;
        case METHODID_DKG_PART1:
          serviceImpl.dkgPart1((com.stakecraft.rutli.grpc.DkgPart1Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply>) responseObserver);
          break;
        case METHODID_DKG_PART2:
          serviceImpl.dkgPart2((com.stakecraft.rutli.grpc.DkgPart2Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply>) responseObserver);
          break;
        case METHODID_DKG_PART3:
          serviceImpl.dkgPart3((com.stakecraft.rutli.grpc.DkgPart3Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply>) responseObserver);
          break;
        case METHODID_REFRESH_PART1:
          serviceImpl.refreshPart1((com.stakecraft.rutli.grpc.RefreshPart1Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart1Reply>) responseObserver);
          break;
        case METHODID_REFRESH_PART2:
          serviceImpl.refreshPart2((com.stakecraft.rutli.grpc.DkgPart2Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart2Reply>) responseObserver);
          break;
        case METHODID_REFRESH_PART3:
          serviceImpl.refreshPart3((com.stakecraft.rutli.grpc.DkgPart3Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.DkgPart3Reply>) responseObserver);
          break;
        case METHODID_ABORT_SIGN:
          serviceImpl.abortSign((com.stakecraft.rutli.grpc.AbortSignRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.AbortSignReply>) responseObserver);
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
          getSignRound1Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.SignRound1Request,
              com.stakecraft.rutli.grpc.SignRound1Reply>(
                service, METHODID_SIGN_ROUND1)))
        .addMethod(
          getSignRound2Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.SignRound2Request,
              com.stakecraft.rutli.grpc.SignRound2Reply>(
                service, METHODID_SIGN_ROUND2)))
        .addMethod(
          getDkgPart1Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgPart1Request,
              com.stakecraft.rutli.grpc.DkgPart1Reply>(
                service, METHODID_DKG_PART1)))
        .addMethod(
          getDkgPart2Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgPart2Request,
              com.stakecraft.rutli.grpc.DkgPart2Reply>(
                service, METHODID_DKG_PART2)))
        .addMethod(
          getDkgPart3Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgPart3Request,
              com.stakecraft.rutli.grpc.DkgPart3Reply>(
                service, METHODID_DKG_PART3)))
        .addMethod(
          getRefreshPart1Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.RefreshPart1Request,
              com.stakecraft.rutli.grpc.DkgPart1Reply>(
                service, METHODID_REFRESH_PART1)))
        .addMethod(
          getRefreshPart2Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgPart2Request,
              com.stakecraft.rutli.grpc.DkgPart2Reply>(
                service, METHODID_REFRESH_PART2)))
        .addMethod(
          getRefreshPart3Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.DkgPart3Request,
              com.stakecraft.rutli.grpc.DkgPart3Reply>(
                service, METHODID_REFRESH_PART3)))
        .addMethod(
          getAbortSignMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.AbortSignRequest,
              com.stakecraft.rutli.grpc.AbortSignReply>(
                service, METHODID_ABORT_SIGN)))
        .build();
  }

  private static abstract class PeerBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    PeerBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.stakecraft.rutli.grpc.CosignerProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("Peer");
    }
  }

  private static final class PeerFileDescriptorSupplier
      extends PeerBaseDescriptorSupplier {
    PeerFileDescriptorSupplier() {}
  }

  private static final class PeerMethodDescriptorSupplier
      extends PeerBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    PeerMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (PeerGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new PeerFileDescriptorSupplier())
              .addMethod(getSignRound1Method())
              .addMethod(getSignRound2Method())
              .addMethod(getDkgPart1Method())
              .addMethod(getDkgPart2Method())
              .addMethod(getDkgPart3Method())
              .addMethod(getRefreshPart1Method())
              .addMethod(getRefreshPart2Method())
              .addMethod(getRefreshPart3Method())
              .addMethod(getAbortSignMethod())
              .build();
        }
      }
    }
    return result;
  }
}
