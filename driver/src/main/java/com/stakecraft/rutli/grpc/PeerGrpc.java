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

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart1Request,
      com.stakecraft.rutli.grpc.CeremonyPart1Reply> getCeremonyPart1Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyPart1",
      requestType = com.stakecraft.rutli.grpc.CeremonyPart1Request.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyPart1Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart1Request,
      com.stakecraft.rutli.grpc.CeremonyPart1Reply> getCeremonyPart1Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart1Request, com.stakecraft.rutli.grpc.CeremonyPart1Reply> getCeremonyPart1Method;
    if ((getCeremonyPart1Method = PeerGrpc.getCeremonyPart1Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyPart1Method = PeerGrpc.getCeremonyPart1Method) == null) {
          PeerGrpc.getCeremonyPart1Method = getCeremonyPart1Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyPart1Request, com.stakecraft.rutli.grpc.CeremonyPart1Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyPart1"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart1Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart1Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyPart1"))
              .build();
        }
      }
    }
    return getCeremonyPart1Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart2Request,
      com.stakecraft.rutli.grpc.CeremonyPart2Reply> getCeremonyPart2Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyPart2",
      requestType = com.stakecraft.rutli.grpc.CeremonyPart2Request.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyPart2Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart2Request,
      com.stakecraft.rutli.grpc.CeremonyPart2Reply> getCeremonyPart2Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart2Request, com.stakecraft.rutli.grpc.CeremonyPart2Reply> getCeremonyPart2Method;
    if ((getCeremonyPart2Method = PeerGrpc.getCeremonyPart2Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyPart2Method = PeerGrpc.getCeremonyPart2Method) == null) {
          PeerGrpc.getCeremonyPart2Method = getCeremonyPart2Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyPart2Request, com.stakecraft.rutli.grpc.CeremonyPart2Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyPart2"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart2Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart2Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyPart2"))
              .build();
        }
      }
    }
    return getCeremonyPart2Method;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyDeliverRequest,
      com.stakecraft.rutli.grpc.CeremonyDeliverReply> getCeremonyDeliverMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyDeliver",
      requestType = com.stakecraft.rutli.grpc.CeremonyDeliverRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyDeliverReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyDeliverRequest,
      com.stakecraft.rutli.grpc.CeremonyDeliverReply> getCeremonyDeliverMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyDeliverRequest, com.stakecraft.rutli.grpc.CeremonyDeliverReply> getCeremonyDeliverMethod;
    if ((getCeremonyDeliverMethod = PeerGrpc.getCeremonyDeliverMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyDeliverMethod = PeerGrpc.getCeremonyDeliverMethod) == null) {
          PeerGrpc.getCeremonyDeliverMethod = getCeremonyDeliverMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyDeliverRequest, com.stakecraft.rutli.grpc.CeremonyDeliverReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyDeliver"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyDeliverRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyDeliverReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyDeliver"))
              .build();
        }
      }
    }
    return getCeremonyDeliverMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart3Request,
      com.stakecraft.rutli.grpc.CeremonyPart3Reply> getCeremonyPart3Method;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyPart3",
      requestType = com.stakecraft.rutli.grpc.CeremonyPart3Request.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyPart3Reply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart3Request,
      com.stakecraft.rutli.grpc.CeremonyPart3Reply> getCeremonyPart3Method() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyPart3Request, com.stakecraft.rutli.grpc.CeremonyPart3Reply> getCeremonyPart3Method;
    if ((getCeremonyPart3Method = PeerGrpc.getCeremonyPart3Method) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyPart3Method = PeerGrpc.getCeremonyPart3Method) == null) {
          PeerGrpc.getCeremonyPart3Method = getCeremonyPart3Method =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyPart3Request, com.stakecraft.rutli.grpc.CeremonyPart3Reply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyPart3"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart3Request.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyPart3Reply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyPart3"))
              .build();
        }
      }
    }
    return getCeremonyPart3Method;
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

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyFenceRequest,
      com.stakecraft.rutli.grpc.CeremonyFenceReply> getCeremonyFenceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyFence",
      requestType = com.stakecraft.rutli.grpc.CeremonyFenceRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyFenceReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyFenceRequest,
      com.stakecraft.rutli.grpc.CeremonyFenceReply> getCeremonyFenceMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyFenceRequest, com.stakecraft.rutli.grpc.CeremonyFenceReply> getCeremonyFenceMethod;
    if ((getCeremonyFenceMethod = PeerGrpc.getCeremonyFenceMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyFenceMethod = PeerGrpc.getCeremonyFenceMethod) == null) {
          PeerGrpc.getCeremonyFenceMethod = getCeremonyFenceMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyFenceRequest, com.stakecraft.rutli.grpc.CeremonyFenceReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyFence"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyFenceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyFenceReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyFence"))
              .build();
        }
      }
    }
    return getCeremonyFenceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyReleaseRequest,
      com.stakecraft.rutli.grpc.CeremonyReleaseReply> getCeremonyReleaseMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyRelease",
      requestType = com.stakecraft.rutli.grpc.CeremonyReleaseRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyReleaseReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyReleaseRequest,
      com.stakecraft.rutli.grpc.CeremonyReleaseReply> getCeremonyReleaseMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyReleaseRequest, com.stakecraft.rutli.grpc.CeremonyReleaseReply> getCeremonyReleaseMethod;
    if ((getCeremonyReleaseMethod = PeerGrpc.getCeremonyReleaseMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyReleaseMethod = PeerGrpc.getCeremonyReleaseMethod) == null) {
          PeerGrpc.getCeremonyReleaseMethod = getCeremonyReleaseMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyReleaseRequest, com.stakecraft.rutli.grpc.CeremonyReleaseReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyRelease"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyReleaseRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyReleaseReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyRelease"))
              .build();
        }
      }
    }
    return getCeremonyReleaseMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ReplicateKeyRequest,
      com.stakecraft.rutli.grpc.ReplicateKeyReply> getReplicateKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ReplicateKey",
      requestType = com.stakecraft.rutli.grpc.ReplicateKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.ReplicateKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ReplicateKeyRequest,
      com.stakecraft.rutli.grpc.ReplicateKeyReply> getReplicateKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ReplicateKeyRequest, com.stakecraft.rutli.grpc.ReplicateKeyReply> getReplicateKeyMethod;
    if ((getReplicateKeyMethod = PeerGrpc.getReplicateKeyMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getReplicateKeyMethod = PeerGrpc.getReplicateKeyMethod) == null) {
          PeerGrpc.getReplicateKeyMethod = getReplicateKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.ReplicateKeyRequest, com.stakecraft.rutli.grpc.ReplicateKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ReplicateKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.ReplicateKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.ReplicateKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("ReplicateKey"))
              .build();
        }
      }
    }
    return getReplicateKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.FetchKeyRequest,
      com.stakecraft.rutli.grpc.FetchKeyReply> getFetchKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "FetchKey",
      requestType = com.stakecraft.rutli.grpc.FetchKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.FetchKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.FetchKeyRequest,
      com.stakecraft.rutli.grpc.FetchKeyReply> getFetchKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.FetchKeyRequest, com.stakecraft.rutli.grpc.FetchKeyReply> getFetchKeyMethod;
    if ((getFetchKeyMethod = PeerGrpc.getFetchKeyMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getFetchKeyMethod = PeerGrpc.getFetchKeyMethod) == null) {
          PeerGrpc.getFetchKeyMethod = getFetchKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.FetchKeyRequest, com.stakecraft.rutli.grpc.FetchKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "FetchKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.FetchKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.FetchKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("FetchKey"))
              .build();
        }
      }
    }
    return getFetchKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ListKeysRequest,
      com.stakecraft.rutli.grpc.ListKeysReply> getListKeysMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListKeys",
      requestType = com.stakecraft.rutli.grpc.ListKeysRequest.class,
      responseType = com.stakecraft.rutli.grpc.ListKeysReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ListKeysRequest,
      com.stakecraft.rutli.grpc.ListKeysReply> getListKeysMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.ListKeysRequest, com.stakecraft.rutli.grpc.ListKeysReply> getListKeysMethod;
    if ((getListKeysMethod = PeerGrpc.getListKeysMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getListKeysMethod = PeerGrpc.getListKeysMethod) == null) {
          PeerGrpc.getListKeysMethod = getListKeysMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.ListKeysRequest, com.stakecraft.rutli.grpc.ListKeysReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListKeys"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.ListKeysRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.ListKeysReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("ListKeys"))
              .build();
        }
      }
    }
    return getListKeysMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PurgeKeyRequest,
      com.stakecraft.rutli.grpc.PurgeKeyReply> getPurgeKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "PurgeKey",
      requestType = com.stakecraft.rutli.grpc.PurgeKeyRequest.class,
      responseType = com.stakecraft.rutli.grpc.PurgeKeyReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PurgeKeyRequest,
      com.stakecraft.rutli.grpc.PurgeKeyReply> getPurgeKeyMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.PurgeKeyRequest, com.stakecraft.rutli.grpc.PurgeKeyReply> getPurgeKeyMethod;
    if ((getPurgeKeyMethod = PeerGrpc.getPurgeKeyMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getPurgeKeyMethod = PeerGrpc.getPurgeKeyMethod) == null) {
          PeerGrpc.getPurgeKeyMethod = getPurgeKeyMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.PurgeKeyRequest, com.stakecraft.rutli.grpc.PurgeKeyReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "PurgeKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.PurgeKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.PurgeKeyReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("PurgeKey"))
              .build();
        }
      }
    }
    return getPurgeKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.NodeInfoRequest,
      com.stakecraft.rutli.grpc.NodeInfoReply> getNodeInfoMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "NodeInfo",
      requestType = com.stakecraft.rutli.grpc.NodeInfoRequest.class,
      responseType = com.stakecraft.rutli.grpc.NodeInfoReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.NodeInfoRequest,
      com.stakecraft.rutli.grpc.NodeInfoReply> getNodeInfoMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.NodeInfoRequest, com.stakecraft.rutli.grpc.NodeInfoReply> getNodeInfoMethod;
    if ((getNodeInfoMethod = PeerGrpc.getNodeInfoMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getNodeInfoMethod = PeerGrpc.getNodeInfoMethod) == null) {
          PeerGrpc.getNodeInfoMethod = getNodeInfoMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.NodeInfoRequest, com.stakecraft.rutli.grpc.NodeInfoReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "NodeInfo"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.NodeInfoRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.NodeInfoReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("NodeInfo"))
              .build();
        }
      }
    }
    return getNodeInfoMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyEpochRequest,
      com.stakecraft.rutli.grpc.KeyEpochReply> getKeyEpochMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "KeyEpoch",
      requestType = com.stakecraft.rutli.grpc.KeyEpochRequest.class,
      responseType = com.stakecraft.rutli.grpc.KeyEpochReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyEpochRequest,
      com.stakecraft.rutli.grpc.KeyEpochReply> getKeyEpochMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.KeyEpochRequest, com.stakecraft.rutli.grpc.KeyEpochReply> getKeyEpochMethod;
    if ((getKeyEpochMethod = PeerGrpc.getKeyEpochMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getKeyEpochMethod = PeerGrpc.getKeyEpochMethod) == null) {
          PeerGrpc.getKeyEpochMethod = getKeyEpochMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.KeyEpochRequest, com.stakecraft.rutli.grpc.KeyEpochReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "KeyEpoch"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyEpochRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.KeyEpochReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("KeyEpoch"))
              .build();
        }
      }
    }
    return getKeyEpochMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyCommitRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyCommitMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyCommit",
      requestType = com.stakecraft.rutli.grpc.CeremonyCommitRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyStatusReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyCommitRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyCommitMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyCommitRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyCommitMethod;
    if ((getCeremonyCommitMethod = PeerGrpc.getCeremonyCommitMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyCommitMethod = PeerGrpc.getCeremonyCommitMethod) == null) {
          PeerGrpc.getCeremonyCommitMethod = getCeremonyCommitMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyCommitRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyCommit"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyCommitRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyStatusReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyCommit"))
              .build();
        }
      }
    }
    return getCeremonyCommitMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyStatusRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyStatusMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyStatus",
      requestType = com.stakecraft.rutli.grpc.CeremonyStatusRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyStatusReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyStatusRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyStatusMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyStatusRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyStatusMethod;
    if ((getCeremonyStatusMethod = PeerGrpc.getCeremonyStatusMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyStatusMethod = PeerGrpc.getCeremonyStatusMethod) == null) {
          PeerGrpc.getCeremonyStatusMethod = getCeremonyStatusMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyStatusRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyStatus"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyStatusRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyStatusReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyStatus"))
              .build();
        }
      }
    }
    return getCeremonyStatusMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyAbortRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyAbortMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CeremonyAbort",
      requestType = com.stakecraft.rutli.grpc.CeremonyAbortRequest.class,
      responseType = com.stakecraft.rutli.grpc.CeremonyStatusReply.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyAbortRequest,
      com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyAbortMethod() {
    io.grpc.MethodDescriptor<com.stakecraft.rutli.grpc.CeremonyAbortRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply> getCeremonyAbortMethod;
    if ((getCeremonyAbortMethod = PeerGrpc.getCeremonyAbortMethod) == null) {
      synchronized (PeerGrpc.class) {
        if ((getCeremonyAbortMethod = PeerGrpc.getCeremonyAbortMethod) == null) {
          PeerGrpc.getCeremonyAbortMethod = getCeremonyAbortMethod =
              io.grpc.MethodDescriptor.<com.stakecraft.rutli.grpc.CeremonyAbortRequest, com.stakecraft.rutli.grpc.CeremonyStatusReply>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CeremonyAbort"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyAbortRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.stakecraft.rutli.grpc.CeremonyStatusReply.getDefaultInstance()))
              .setSchemaDescriptor(new PeerMethodDescriptorSupplier("CeremonyAbort"))
              .build();
        }
      }
    }
    return getCeremonyAbortMethod;
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
     * <pre>
     * Ceremony protocol 1 (leader-relayed round 2 — audit C1). Retained ONLY so that a node of this
     * release refuses an older leader loudly: every one of these answers FAILED_PRECONDITION.
     * </pre>
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
     * Ceremony protocol 2 (DKG and refresh share one path). The leader coordinates only: it never
     * sees a round-2 package. Part 2 makes each node deliver its round-2 packages DIRECTLY to their
     * recipients (CeremonyDeliver, node to node over mTLS), and every delivery carries the sender's
     * digest of the round-1 map, so a leader that shows nodes different maps makes all abort. Part 3
     * stages the new share and records a yes-vote; CeremonyCommit then resolves (two-phase commit).
     * </pre>
     */
    default void ceremonyPart1(com.stakecraft.rutli.grpc.CeremonyPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart1Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyPart1Method(), responseObserver);
    }

    /**
     */
    default void ceremonyPart2(com.stakecraft.rutli.grpc.CeremonyPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart2Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyPart2Method(), responseObserver);
    }

    /**
     * <pre>
     * Sender -&gt; recipient. The recipient takes the sender from the caller's certificate CN (exact
     * roster mapping) and refuses a `from` that differs, or a `to` that is not itself.
     * </pre>
     */
    default void ceremonyDeliver(com.stakecraft.rutli.grpc.CeremonyDeliverRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyDeliverReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyDeliverMethod(), responseObserver);
    }

    /**
     */
    default void ceremonyPart3(com.stakecraft.rutli.grpc.CeremonyPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart3Reply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyPart3Method(), responseObserver);
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

    /**
     * <pre>
     * Cluster-wide ceremony fence: take the per-key guard on every peer BEFORE DKG/refresh crypto,
     * so no node can start a new sign while the ceremony is in flight. Release rolls back a partial
     * fence if a later peer refuses (e.g. has in-flight signs).
     * </pre>
     */
    default void ceremonyFence(com.stakecraft.rutli.grpc.CeremonyFenceRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyFenceReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyFenceMethod(), responseObserver);
    }

    /**
     */
    default void ceremonyRelease(com.stakecraft.rutli.grpc.CeremonyReleaseRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyReleaseReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyReleaseMethod(), responseObserver);
    }

    /**
     * <pre>
     * Push a wrapped hosted key to this node (leader -&gt; peer during generation).
     * </pre>
     */
    default void replicateKey(com.stakecraft.rutli.grpc.ReplicateKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ReplicateKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getReplicateKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * Pull a hosted key this node is missing (anti-entropy / read-repair). The responder wraps to
     * the *caller's* node identity, derived from its client certificate.
     * </pre>
     */
    default void fetchKey(com.stakecraft.rutli.grpc.FetchKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.FetchKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getFetchKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * Hosted-key inventory for anti-entropy. FROST shares are never listed or transferred — copying
     * a share would give two nodes the same share and silently break the threshold scheme.
     * </pre>
     */
    default void listKeys(com.stakecraft.rutli.grpc.ListKeysRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ListKeysReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListKeysMethod(), responseObserver);
    }

    /**
     * <pre>
     * Replicated delete: with a delete intent, this node verifies it and tombstones the key. Without
     * one, only the rollback of a key this node stored in the same, still-fenced generation that did
     * not reach its write quorum (genkey ceremony id) — anything else is refused.
     * </pre>
     */
    default void purgeKey(com.stakecraft.rutli.grpc.PurgeKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PurgeKeyReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getPurgeKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * This node's identifier and X25519 distribution public key (for wrapping hosted keys to it).
     * </pre>
     */
    default void nodeInfo(com.stakecraft.rutli.grpc.NodeInfoRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.NodeInfoReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getNodeInfoMethod(), responseObserver);
    }

    /**
     * <pre>
     * --- two-phase ceremonies (DKG/refresh) ---
     * This node's committed epoch and PKP digest for one FROST key, and whether a ceremony for it is
     * staged here. Public values only. The leader asks every node before a DKG (idempotent retry)
     * or a refresh (every node must be on the same sharing).
     * </pre>
     */
    default void keyEpoch(com.stakecraft.rutli.grpc.KeyEpochRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyEpochReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getKeyEpochMethod(), responseObserver);
    }

    /**
     * <pre>
     * Resolve a ceremony this node STAGED, now: it asks every roster node for its vote DIRECTLY and
     * commits only if all of them hold a yes-vote for the same outcome, aborts only on a no-vote or a
     * divergent one, else stays STAGED (its background resolver keeps asking). The caller's word is
     * never evidence. Returns where the ceremony stands on this node afterwards.
     * </pre>
     */
    default void ceremonyCommit(com.stakecraft.rutli.grpc.CeremonyCommitRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyCommitMethod(), responseObserver);
    }

    /**
     * <pre>
     * This node's vote on a ceremony. A node with neither a session nor a record durably votes
     * ABORTED before it answers, so an answer never changes later.
     * </pre>
     */
    default void ceremonyStatus(com.stakecraft.rutli.grpc.CeremonyStatusRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyStatusMethod(), responseObserver);
    }

    /**
     * <pre>
     * The leader gives up: drops this node's in-memory session (recording ABORTED). A recorded vote
     * (STAGED included) is returned unchanged.
     * </pre>
     */
    default void ceremonyAbort(com.stakecraft.rutli.grpc.CeremonyAbortRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCeremonyAbortMethod(), responseObserver);
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
     * <pre>
     * Ceremony protocol 1 (leader-relayed round 2 — audit C1). Retained ONLY so that a node of this
     * release refuses an older leader loudly: every one of these answers FAILED_PRECONDITION.
     * </pre>
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
     * Ceremony protocol 2 (DKG and refresh share one path). The leader coordinates only: it never
     * sees a round-2 package. Part 2 makes each node deliver its round-2 packages DIRECTLY to their
     * recipients (CeremonyDeliver, node to node over mTLS), and every delivery carries the sender's
     * digest of the round-1 map, so a leader that shows nodes different maps makes all abort. Part 3
     * stages the new share and records a yes-vote; CeremonyCommit then resolves (two-phase commit).
     * </pre>
     */
    public void ceremonyPart1(com.stakecraft.rutli.grpc.CeremonyPart1Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart1Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyPart1Method(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void ceremonyPart2(com.stakecraft.rutli.grpc.CeremonyPart2Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart2Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyPart2Method(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Sender -&gt; recipient. The recipient takes the sender from the caller's certificate CN (exact
     * roster mapping) and refuses a `from` that differs, or a `to` that is not itself.
     * </pre>
     */
    public void ceremonyDeliver(com.stakecraft.rutli.grpc.CeremonyDeliverRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyDeliverReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyDeliverMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void ceremonyPart3(com.stakecraft.rutli.grpc.CeremonyPart3Request request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart3Reply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyPart3Method(), getCallOptions()), request, responseObserver);
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

    /**
     * <pre>
     * Cluster-wide ceremony fence: take the per-key guard on every peer BEFORE DKG/refresh crypto,
     * so no node can start a new sign while the ceremony is in flight. Release rolls back a partial
     * fence if a later peer refuses (e.g. has in-flight signs).
     * </pre>
     */
    public void ceremonyFence(com.stakecraft.rutli.grpc.CeremonyFenceRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyFenceReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyFenceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void ceremonyRelease(com.stakecraft.rutli.grpc.CeremonyReleaseRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyReleaseReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyReleaseMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Push a wrapped hosted key to this node (leader -&gt; peer during generation).
     * </pre>
     */
    public void replicateKey(com.stakecraft.rutli.grpc.ReplicateKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ReplicateKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getReplicateKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Pull a hosted key this node is missing (anti-entropy / read-repair). The responder wraps to
     * the *caller's* node identity, derived from its client certificate.
     * </pre>
     */
    public void fetchKey(com.stakecraft.rutli.grpc.FetchKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.FetchKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getFetchKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Hosted-key inventory for anti-entropy. FROST shares are never listed or transferred — copying
     * a share would give two nodes the same share and silently break the threshold scheme.
     * </pre>
     */
    public void listKeys(com.stakecraft.rutli.grpc.ListKeysRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ListKeysReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListKeysMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Replicated delete: with a delete intent, this node verifies it and tombstones the key. Without
     * one, only the rollback of a key this node stored in the same, still-fenced generation that did
     * not reach its write quorum (genkey ceremony id) — anything else is refused.
     * </pre>
     */
    public void purgeKey(com.stakecraft.rutli.grpc.PurgeKeyRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PurgeKeyReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getPurgeKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * This node's identifier and X25519 distribution public key (for wrapping hosted keys to it).
     * </pre>
     */
    public void nodeInfo(com.stakecraft.rutli.grpc.NodeInfoRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.NodeInfoReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getNodeInfoMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * --- two-phase ceremonies (DKG/refresh) ---
     * This node's committed epoch and PKP digest for one FROST key, and whether a ceremony for it is
     * staged here. Public values only. The leader asks every node before a DKG (idempotent retry)
     * or a refresh (every node must be on the same sharing).
     * </pre>
     */
    public void keyEpoch(com.stakecraft.rutli.grpc.KeyEpochRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyEpochReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getKeyEpochMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Resolve a ceremony this node STAGED, now: it asks every roster node for its vote DIRECTLY and
     * commits only if all of them hold a yes-vote for the same outcome, aborts only on a no-vote or a
     * divergent one, else stays STAGED (its background resolver keeps asking). The caller's word is
     * never evidence. Returns where the ceremony stands on this node afterwards.
     * </pre>
     */
    public void ceremonyCommit(com.stakecraft.rutli.grpc.CeremonyCommitRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyCommitMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * This node's vote on a ceremony. A node with neither a session nor a record durably votes
     * ABORTED before it answers, so an answer never changes later.
     * </pre>
     */
    public void ceremonyStatus(com.stakecraft.rutli.grpc.CeremonyStatusRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyStatusMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * The leader gives up: drops this node's in-memory session (recording ABORTED). A recorded vote
     * (STAGED included) is returned unchanged.
     * </pre>
     */
    public void ceremonyAbort(com.stakecraft.rutli.grpc.CeremonyAbortRequest request,
        io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCeremonyAbortMethod(), getCallOptions()), request, responseObserver);
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
     * <pre>
     * Ceremony protocol 1 (leader-relayed round 2 — audit C1). Retained ONLY so that a node of this
     * release refuses an older leader loudly: every one of these answers FAILED_PRECONDITION.
     * </pre>
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
     * Ceremony protocol 2 (DKG and refresh share one path). The leader coordinates only: it never
     * sees a round-2 package. Part 2 makes each node deliver its round-2 packages DIRECTLY to their
     * recipients (CeremonyDeliver, node to node over mTLS), and every delivery carries the sender's
     * digest of the round-1 map, so a leader that shows nodes different maps makes all abort. Part 3
     * stages the new share and records a yes-vote; CeremonyCommit then resolves (two-phase commit).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyPart1Reply ceremonyPart1(com.stakecraft.rutli.grpc.CeremonyPart1Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyPart2Reply ceremonyPart2(com.stakecraft.rutli.grpc.CeremonyPart2Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyPart2Method(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Sender -&gt; recipient. The recipient takes the sender from the caller's certificate CN (exact
     * roster mapping) and refuses a `from` that differs, or a `to` that is not itself.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyDeliverReply ceremonyDeliver(com.stakecraft.rutli.grpc.CeremonyDeliverRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyDeliverMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyPart3Reply ceremonyPart3(com.stakecraft.rutli.grpc.CeremonyPart3Request request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyPart3Method(), getCallOptions(), request);
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

    /**
     * <pre>
     * Cluster-wide ceremony fence: take the per-key guard on every peer BEFORE DKG/refresh crypto,
     * so no node can start a new sign while the ceremony is in flight. Release rolls back a partial
     * fence if a later peer refuses (e.g. has in-flight signs).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyFenceReply ceremonyFence(com.stakecraft.rutli.grpc.CeremonyFenceRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyFenceMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyReleaseReply ceremonyRelease(com.stakecraft.rutli.grpc.CeremonyReleaseRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyReleaseMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Push a wrapped hosted key to this node (leader -&gt; peer during generation).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.ReplicateKeyReply replicateKey(com.stakecraft.rutli.grpc.ReplicateKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getReplicateKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Pull a hosted key this node is missing (anti-entropy / read-repair). The responder wraps to
     * the *caller's* node identity, derived from its client certificate.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.FetchKeyReply fetchKey(com.stakecraft.rutli.grpc.FetchKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getFetchKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Hosted-key inventory for anti-entropy. FROST shares are never listed or transferred — copying
     * a share would give two nodes the same share and silently break the threshold scheme.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.ListKeysReply listKeys(com.stakecraft.rutli.grpc.ListKeysRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getListKeysMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Replicated delete: with a delete intent, this node verifies it and tombstones the key. Without
     * one, only the rollback of a key this node stored in the same, still-fenced generation that did
     * not reach its write quorum (genkey ceremony id) — anything else is refused.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.PurgeKeyReply purgeKey(com.stakecraft.rutli.grpc.PurgeKeyRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getPurgeKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's identifier and X25519 distribution public key (for wrapping hosted keys to it).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.NodeInfoReply nodeInfo(com.stakecraft.rutli.grpc.NodeInfoRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getNodeInfoMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * --- two-phase ceremonies (DKG/refresh) ---
     * This node's committed epoch and PKP digest for one FROST key, and whether a ceremony for it is
     * staged here. Public values only. The leader asks every node before a DKG (idempotent retry)
     * or a refresh (every node must be on the same sharing).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.KeyEpochReply keyEpoch(com.stakecraft.rutli.grpc.KeyEpochRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getKeyEpochMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Resolve a ceremony this node STAGED, now: it asks every roster node for its vote DIRECTLY and
     * commits only if all of them hold a yes-vote for the same outcome, aborts only on a no-vote or a
     * divergent one, else stays STAGED (its background resolver keeps asking). The caller's word is
     * never evidence. Returns where the ceremony stands on this node afterwards.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyCommit(com.stakecraft.rutli.grpc.CeremonyCommitRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyCommitMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's vote on a ceremony. A node with neither a session nor a record durably votes
     * ABORTED before it answers, so an answer never changes later.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyStatus(com.stakecraft.rutli.grpc.CeremonyStatusRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyStatusMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * The leader gives up: drops this node's in-memory session (recording ABORTED). A recorded vote
     * (STAGED included) is returned unchanged.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyAbort(com.stakecraft.rutli.grpc.CeremonyAbortRequest request) throws io.grpc.StatusException {
      return io.grpc.stub.ClientCalls.blockingV2UnaryCall(
          getChannel(), getCeremonyAbortMethod(), getCallOptions(), request);
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
     * <pre>
     * Ceremony protocol 1 (leader-relayed round 2 — audit C1). Retained ONLY so that a node of this
     * release refuses an older leader loudly: every one of these answers FAILED_PRECONDITION.
     * </pre>
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
     * Ceremony protocol 2 (DKG and refresh share one path). The leader coordinates only: it never
     * sees a round-2 package. Part 2 makes each node deliver its round-2 packages DIRECTLY to their
     * recipients (CeremonyDeliver, node to node over mTLS), and every delivery carries the sender's
     * digest of the round-1 map, so a leader that shows nodes different maps makes all abort. Part 3
     * stages the new share and records a yes-vote; CeremonyCommit then resolves (two-phase commit).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyPart1Reply ceremonyPart1(com.stakecraft.rutli.grpc.CeremonyPart1Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyPart1Method(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyPart2Reply ceremonyPart2(com.stakecraft.rutli.grpc.CeremonyPart2Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyPart2Method(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Sender -&gt; recipient. The recipient takes the sender from the caller's certificate CN (exact
     * roster mapping) and refuses a `from` that differs, or a `to` that is not itself.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyDeliverReply ceremonyDeliver(com.stakecraft.rutli.grpc.CeremonyDeliverRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyDeliverMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyPart3Reply ceremonyPart3(com.stakecraft.rutli.grpc.CeremonyPart3Request request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyPart3Method(), getCallOptions(), request);
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

    /**
     * <pre>
     * Cluster-wide ceremony fence: take the per-key guard on every peer BEFORE DKG/refresh crypto,
     * so no node can start a new sign while the ceremony is in flight. Release rolls back a partial
     * fence if a later peer refuses (e.g. has in-flight signs).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyFenceReply ceremonyFence(com.stakecraft.rutli.grpc.CeremonyFenceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyFenceMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.stakecraft.rutli.grpc.CeremonyReleaseReply ceremonyRelease(com.stakecraft.rutli.grpc.CeremonyReleaseRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyReleaseMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Push a wrapped hosted key to this node (leader -&gt; peer during generation).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.ReplicateKeyReply replicateKey(com.stakecraft.rutli.grpc.ReplicateKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getReplicateKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Pull a hosted key this node is missing (anti-entropy / read-repair). The responder wraps to
     * the *caller's* node identity, derived from its client certificate.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.FetchKeyReply fetchKey(com.stakecraft.rutli.grpc.FetchKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getFetchKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Hosted-key inventory for anti-entropy. FROST shares are never listed or transferred — copying
     * a share would give two nodes the same share and silently break the threshold scheme.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.ListKeysReply listKeys(com.stakecraft.rutli.grpc.ListKeysRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListKeysMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Replicated delete: with a delete intent, this node verifies it and tombstones the key. Without
     * one, only the rollback of a key this node stored in the same, still-fenced generation that did
     * not reach its write quorum (genkey ceremony id) — anything else is refused.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.PurgeKeyReply purgeKey(com.stakecraft.rutli.grpc.PurgeKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getPurgeKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's identifier and X25519 distribution public key (for wrapping hosted keys to it).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.NodeInfoReply nodeInfo(com.stakecraft.rutli.grpc.NodeInfoRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getNodeInfoMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * --- two-phase ceremonies (DKG/refresh) ---
     * This node's committed epoch and PKP digest for one FROST key, and whether a ceremony for it is
     * staged here. Public values only. The leader asks every node before a DKG (idempotent retry)
     * or a refresh (every node must be on the same sharing).
     * </pre>
     */
    public com.stakecraft.rutli.grpc.KeyEpochReply keyEpoch(com.stakecraft.rutli.grpc.KeyEpochRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getKeyEpochMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Resolve a ceremony this node STAGED, now: it asks every roster node for its vote DIRECTLY and
     * commits only if all of them hold a yes-vote for the same outcome, aborts only on a no-vote or a
     * divergent one, else stays STAGED (its background resolver keeps asking). The caller's word is
     * never evidence. Returns where the ceremony stands on this node afterwards.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyCommit(com.stakecraft.rutli.grpc.CeremonyCommitRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyCommitMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * This node's vote on a ceremony. A node with neither a session nor a record durably votes
     * ABORTED before it answers, so an answer never changes later.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyStatus(com.stakecraft.rutli.grpc.CeremonyStatusRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyStatusMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * The leader gives up: drops this node's in-memory session (recording ABORTED). A recorded vote
     * (STAGED included) is returned unchanged.
     * </pre>
     */
    public com.stakecraft.rutli.grpc.CeremonyStatusReply ceremonyAbort(com.stakecraft.rutli.grpc.CeremonyAbortRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCeremonyAbortMethod(), getCallOptions(), request);
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
     * <pre>
     * Ceremony protocol 1 (leader-relayed round 2 — audit C1). Retained ONLY so that a node of this
     * release refuses an older leader loudly: every one of these answers FAILED_PRECONDITION.
     * </pre>
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
     * Ceremony protocol 2 (DKG and refresh share one path). The leader coordinates only: it never
     * sees a round-2 package. Part 2 makes each node deliver its round-2 packages DIRECTLY to their
     * recipients (CeremonyDeliver, node to node over mTLS), and every delivery carries the sender's
     * digest of the round-1 map, so a leader that shows nodes different maps makes all abort. Part 3
     * stages the new share and records a yes-vote; CeremonyCommit then resolves (two-phase commit).
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyPart1Reply> ceremonyPart1(
        com.stakecraft.rutli.grpc.CeremonyPart1Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyPart1Method(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyPart2Reply> ceremonyPart2(
        com.stakecraft.rutli.grpc.CeremonyPart2Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyPart2Method(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Sender -&gt; recipient. The recipient takes the sender from the caller's certificate CN (exact
     * roster mapping) and refuses a `from` that differs, or a `to` that is not itself.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyDeliverReply> ceremonyDeliver(
        com.stakecraft.rutli.grpc.CeremonyDeliverRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyDeliverMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyPart3Reply> ceremonyPart3(
        com.stakecraft.rutli.grpc.CeremonyPart3Request request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyPart3Method(), getCallOptions()), request);
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

    /**
     * <pre>
     * Cluster-wide ceremony fence: take the per-key guard on every peer BEFORE DKG/refresh crypto,
     * so no node can start a new sign while the ceremony is in flight. Release rolls back a partial
     * fence if a later peer refuses (e.g. has in-flight signs).
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyFenceReply> ceremonyFence(
        com.stakecraft.rutli.grpc.CeremonyFenceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyFenceMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyReleaseReply> ceremonyRelease(
        com.stakecraft.rutli.grpc.CeremonyReleaseRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyReleaseMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Push a wrapped hosted key to this node (leader -&gt; peer during generation).
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.ReplicateKeyReply> replicateKey(
        com.stakecraft.rutli.grpc.ReplicateKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getReplicateKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Pull a hosted key this node is missing (anti-entropy / read-repair). The responder wraps to
     * the *caller's* node identity, derived from its client certificate.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.FetchKeyReply> fetchKey(
        com.stakecraft.rutli.grpc.FetchKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getFetchKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Hosted-key inventory for anti-entropy. FROST shares are never listed or transferred — copying
     * a share would give two nodes the same share and silently break the threshold scheme.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.ListKeysReply> listKeys(
        com.stakecraft.rutli.grpc.ListKeysRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListKeysMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Replicated delete: with a delete intent, this node verifies it and tombstones the key. Without
     * one, only the rollback of a key this node stored in the same, still-fenced generation that did
     * not reach its write quorum (genkey ceremony id) — anything else is refused.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.PurgeKeyReply> purgeKey(
        com.stakecraft.rutli.grpc.PurgeKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getPurgeKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * This node's identifier and X25519 distribution public key (for wrapping hosted keys to it).
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.NodeInfoReply> nodeInfo(
        com.stakecraft.rutli.grpc.NodeInfoRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getNodeInfoMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * --- two-phase ceremonies (DKG/refresh) ---
     * This node's committed epoch and PKP digest for one FROST key, and whether a ceremony for it is
     * staged here. Public values only. The leader asks every node before a DKG (idempotent retry)
     * or a refresh (every node must be on the same sharing).
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.KeyEpochReply> keyEpoch(
        com.stakecraft.rutli.grpc.KeyEpochRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getKeyEpochMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Resolve a ceremony this node STAGED, now: it asks every roster node for its vote DIRECTLY and
     * commits only if all of them hold a yes-vote for the same outcome, aborts only on a no-vote or a
     * divergent one, else stays STAGED (its background resolver keeps asking). The caller's word is
     * never evidence. Returns where the ceremony stands on this node afterwards.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyStatusReply> ceremonyCommit(
        com.stakecraft.rutli.grpc.CeremonyCommitRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyCommitMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * This node's vote on a ceremony. A node with neither a session nor a record durably votes
     * ABORTED before it answers, so an answer never changes later.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyStatusReply> ceremonyStatus(
        com.stakecraft.rutli.grpc.CeremonyStatusRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyStatusMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * The leader gives up: drops this node's in-memory session (recording ABORTED). A recorded vote
     * (STAGED included) is returned unchanged.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.stakecraft.rutli.grpc.CeremonyStatusReply> ceremonyAbort(
        com.stakecraft.rutli.grpc.CeremonyAbortRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCeremonyAbortMethod(), getCallOptions()), request);
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
  private static final int METHODID_CEREMONY_PART1 = 8;
  private static final int METHODID_CEREMONY_PART2 = 9;
  private static final int METHODID_CEREMONY_DELIVER = 10;
  private static final int METHODID_CEREMONY_PART3 = 11;
  private static final int METHODID_ABORT_SIGN = 12;
  private static final int METHODID_CEREMONY_FENCE = 13;
  private static final int METHODID_CEREMONY_RELEASE = 14;
  private static final int METHODID_REPLICATE_KEY = 15;
  private static final int METHODID_FETCH_KEY = 16;
  private static final int METHODID_LIST_KEYS = 17;
  private static final int METHODID_PURGE_KEY = 18;
  private static final int METHODID_NODE_INFO = 19;
  private static final int METHODID_KEY_EPOCH = 20;
  private static final int METHODID_CEREMONY_COMMIT = 21;
  private static final int METHODID_CEREMONY_STATUS = 22;
  private static final int METHODID_CEREMONY_ABORT = 23;

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
        case METHODID_CEREMONY_PART1:
          serviceImpl.ceremonyPart1((com.stakecraft.rutli.grpc.CeremonyPart1Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart1Reply>) responseObserver);
          break;
        case METHODID_CEREMONY_PART2:
          serviceImpl.ceremonyPart2((com.stakecraft.rutli.grpc.CeremonyPart2Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart2Reply>) responseObserver);
          break;
        case METHODID_CEREMONY_DELIVER:
          serviceImpl.ceremonyDeliver((com.stakecraft.rutli.grpc.CeremonyDeliverRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyDeliverReply>) responseObserver);
          break;
        case METHODID_CEREMONY_PART3:
          serviceImpl.ceremonyPart3((com.stakecraft.rutli.grpc.CeremonyPart3Request) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyPart3Reply>) responseObserver);
          break;
        case METHODID_ABORT_SIGN:
          serviceImpl.abortSign((com.stakecraft.rutli.grpc.AbortSignRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.AbortSignReply>) responseObserver);
          break;
        case METHODID_CEREMONY_FENCE:
          serviceImpl.ceremonyFence((com.stakecraft.rutli.grpc.CeremonyFenceRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyFenceReply>) responseObserver);
          break;
        case METHODID_CEREMONY_RELEASE:
          serviceImpl.ceremonyRelease((com.stakecraft.rutli.grpc.CeremonyReleaseRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyReleaseReply>) responseObserver);
          break;
        case METHODID_REPLICATE_KEY:
          serviceImpl.replicateKey((com.stakecraft.rutli.grpc.ReplicateKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ReplicateKeyReply>) responseObserver);
          break;
        case METHODID_FETCH_KEY:
          serviceImpl.fetchKey((com.stakecraft.rutli.grpc.FetchKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.FetchKeyReply>) responseObserver);
          break;
        case METHODID_LIST_KEYS:
          serviceImpl.listKeys((com.stakecraft.rutli.grpc.ListKeysRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.ListKeysReply>) responseObserver);
          break;
        case METHODID_PURGE_KEY:
          serviceImpl.purgeKey((com.stakecraft.rutli.grpc.PurgeKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.PurgeKeyReply>) responseObserver);
          break;
        case METHODID_NODE_INFO:
          serviceImpl.nodeInfo((com.stakecraft.rutli.grpc.NodeInfoRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.NodeInfoReply>) responseObserver);
          break;
        case METHODID_KEY_EPOCH:
          serviceImpl.keyEpoch((com.stakecraft.rutli.grpc.KeyEpochRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.KeyEpochReply>) responseObserver);
          break;
        case METHODID_CEREMONY_COMMIT:
          serviceImpl.ceremonyCommit((com.stakecraft.rutli.grpc.CeremonyCommitRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply>) responseObserver);
          break;
        case METHODID_CEREMONY_STATUS:
          serviceImpl.ceremonyStatus((com.stakecraft.rutli.grpc.CeremonyStatusRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply>) responseObserver);
          break;
        case METHODID_CEREMONY_ABORT:
          serviceImpl.ceremonyAbort((com.stakecraft.rutli.grpc.CeremonyAbortRequest) request,
              (io.grpc.stub.StreamObserver<com.stakecraft.rutli.grpc.CeremonyStatusReply>) responseObserver);
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
          getCeremonyPart1Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyPart1Request,
              com.stakecraft.rutli.grpc.CeremonyPart1Reply>(
                service, METHODID_CEREMONY_PART1)))
        .addMethod(
          getCeremonyPart2Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyPart2Request,
              com.stakecraft.rutli.grpc.CeremonyPart2Reply>(
                service, METHODID_CEREMONY_PART2)))
        .addMethod(
          getCeremonyDeliverMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyDeliverRequest,
              com.stakecraft.rutli.grpc.CeremonyDeliverReply>(
                service, METHODID_CEREMONY_DELIVER)))
        .addMethod(
          getCeremonyPart3Method(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyPart3Request,
              com.stakecraft.rutli.grpc.CeremonyPart3Reply>(
                service, METHODID_CEREMONY_PART3)))
        .addMethod(
          getAbortSignMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.AbortSignRequest,
              com.stakecraft.rutli.grpc.AbortSignReply>(
                service, METHODID_ABORT_SIGN)))
        .addMethod(
          getCeremonyFenceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyFenceRequest,
              com.stakecraft.rutli.grpc.CeremonyFenceReply>(
                service, METHODID_CEREMONY_FENCE)))
        .addMethod(
          getCeremonyReleaseMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyReleaseRequest,
              com.stakecraft.rutli.grpc.CeremonyReleaseReply>(
                service, METHODID_CEREMONY_RELEASE)))
        .addMethod(
          getReplicateKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.ReplicateKeyRequest,
              com.stakecraft.rutli.grpc.ReplicateKeyReply>(
                service, METHODID_REPLICATE_KEY)))
        .addMethod(
          getFetchKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.FetchKeyRequest,
              com.stakecraft.rutli.grpc.FetchKeyReply>(
                service, METHODID_FETCH_KEY)))
        .addMethod(
          getListKeysMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.ListKeysRequest,
              com.stakecraft.rutli.grpc.ListKeysReply>(
                service, METHODID_LIST_KEYS)))
        .addMethod(
          getPurgeKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.PurgeKeyRequest,
              com.stakecraft.rutli.grpc.PurgeKeyReply>(
                service, METHODID_PURGE_KEY)))
        .addMethod(
          getNodeInfoMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.NodeInfoRequest,
              com.stakecraft.rutli.grpc.NodeInfoReply>(
                service, METHODID_NODE_INFO)))
        .addMethod(
          getKeyEpochMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.KeyEpochRequest,
              com.stakecraft.rutli.grpc.KeyEpochReply>(
                service, METHODID_KEY_EPOCH)))
        .addMethod(
          getCeremonyCommitMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyCommitRequest,
              com.stakecraft.rutli.grpc.CeremonyStatusReply>(
                service, METHODID_CEREMONY_COMMIT)))
        .addMethod(
          getCeremonyStatusMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyStatusRequest,
              com.stakecraft.rutli.grpc.CeremonyStatusReply>(
                service, METHODID_CEREMONY_STATUS)))
        .addMethod(
          getCeremonyAbortMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.stakecraft.rutli.grpc.CeremonyAbortRequest,
              com.stakecraft.rutli.grpc.CeremonyStatusReply>(
                service, METHODID_CEREMONY_ABORT)))
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
              .addMethod(getCeremonyPart1Method())
              .addMethod(getCeremonyPart2Method())
              .addMethod(getCeremonyDeliverMethod())
              .addMethod(getCeremonyPart3Method())
              .addMethod(getAbortSignMethod())
              .addMethod(getCeremonyFenceMethod())
              .addMethod(getCeremonyReleaseMethod())
              .addMethod(getReplicateKeyMethod())
              .addMethod(getFetchKeyMethod())
              .addMethod(getListKeysMethod())
              .addMethod(getPurgeKeyMethod())
              .addMethod(getNodeInfoMethod())
              .addMethod(getKeyEpochMethod())
              .addMethod(getCeremonyCommitMethod())
              .addMethod(getCeremonyStatusMethod())
              .addMethod(getCeremonyAbortMethod())
              .build();
        }
      }
    }
    return result;
  }
}
