# Specify the Dart SDK base image version using dart:<version> (ex: dart:2.12)
#FROM dart:stable AS build
# FROM ubuntu:21.04 AS build
FROM google/dart as build

RUN mkdir /src
WORKDIR /src
RUN git clone https://github.com/noojee/batman.git

ENV TZ=Australia/Melbourne 
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone RUN dpkg-reconfigure -f noninteractive tzdata

# remove the git clone and uncomment this lines for local dev.
# COPY dcli /src/dcli
# COPY dcli_core /src/dcli_core
# COPY batman /src/batman

WORKDIR /src/batman

RUN dart pub get
RUN dart compile exe /src/batman/bin/batman.dart -o /batman


# Build minimal  image from AOT-compiled `/batman`
FROM build
COPY --from=build /batman /batman
WORKDIR /
RUN /batman install

# schedule scans.
ENTRYPOINT ["/batman", "--quiet", "--no-colour", "cron","30 22 * * * *"]

# remove the ENTRYPOINT and uncomment this line to enable interactive debugging.
# CMD ["bash"]
