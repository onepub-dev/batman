# Specify the Dart SDK base image version using dart:<version> (ex: dart:2.12)
#FROM dart:stable AS build
# FROM ubuntu:21.04 AS build
FROM google/dart

# RUN apt update
# RUN apt install -y dart
# Resolve app dependencies.
# RUN git clone https://github.com/noojee/pci_file_monitor.git
COPY pci_file_monitor
COPY dcli dcli
COPY dcli_core dcli_core

RUN cd pci_file_monitor
WORKDIR /pci_file_monitor
RUN dart pub get
RUN dart compile exe bin/pcifim.dart -o /pcifim


# Build minimal serving image from AOT-compiled `/server` and required system
# libraries and configuration files stored in `/runtime/` from the build stage.
# FROM build
#COPY --from=build /runtime/ /
# COPY --from=build /pcifim/pci_file_monitor/bin/pcifim.exe /pcifim/bin/pcifim
WORKDIR /
# RUN ls -laR /pcifim
RUN ls -la /pcifim
# COPY /pci_file_monitor/bin/pcifim.exe /pcifim
# RUN /pcifim install -v
RUN ls /bin/bash
RUN /bin/bash -c echo hi

# Run a base line and schedule scans.
#ENTRYPOINT ["/pcifim", "cron", "--insecure", "--baseline", "30 22 * * *"]
CMD ["bash"]
#ENTRYPOINT ["bash", '-c", "bash']
