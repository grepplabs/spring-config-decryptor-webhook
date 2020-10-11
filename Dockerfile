FROM golang:1.14-alpine3.12 as builder

RUN apk add alpine-sdk ca-certificates

WORKDIR "/code"
COPY . "/code"
RUN make BINARY=spring-config-decryptor-webhook clean build

FROM alpine:3.12
COPY --from=builder /code/spring-config-decryptor-webhook /spring-config-decryptor-webhook
ENTRYPOINT ["/spring-config-decryptor-webhook"]
