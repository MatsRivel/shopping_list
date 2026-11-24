FROM rust:1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir src static && echo 'fn main(){}' > src/main.rs && touch static/index.html \
    && cargo build --release --locked && rm -rf src static
COPY src src
COPY static static
RUN touch src/main.rs && cargo build --release --locked

FROM debian:stable-slim
RUN useradd -u 10001 app && mkdir /data && chown app /data
COPY --from=build /src/target/release/shopping_list /usr/local/bin/shopping_list
USER 10001
ENV DB_PATH=/data/shopping.db
EXPOSE 8080
CMD ["shopping_list"]
