# Specify the Dart SDK base image version using dart:<version> (ex: dart:2.12)
#FROM dart:stable AS build
# FROM ubuntu:21.04 AS build
FROM google/dart as build

RUN mkdir /src
WORKDIR /src
RUN git clone https://github.com/noojee/pci_file_monitor.git

# remove the git clone and uncomment this lines for local dev.
# COPY dcli /src/dcli
# COPY dcli_core /src/dcli_core
# COPY pci_file_monitor /src/pci_file_monitor

WORKDIR /src/pci_file_monitor

RUN dart pub get
RUN dart compile exe /src/pci_file_monitor/bin/pcifim.dart -o /pcifim


# Build minimal  image from AOT-compiled `/pcifim`
FROM build
COPY --from=build /pcifim /pcifim
WORKDIR /
RUN /pcifim install

# Run a base line and schedule scans.
ENTRYPOINT ["/pcifim", "--quiet", "--no-colour", "cron", "--baseline", "30 22 * * * *"]

# remove the ENTRYPOINT and uncomment this line to enable interactive debugging.
# CMD ["bash"]
