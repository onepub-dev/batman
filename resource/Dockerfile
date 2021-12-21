FROM google/dart as build

ENV TZ=Australia/Melbourne 
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone RUN dpkg-reconfigure -f noninteractive tzdata

RUN mkdir /src
WORKDIR /src
RUN mkdir -p /BUILD_TOKEN/263a4926e95246f095e0de690b0f71ab
RUN git clone https://github.com/noojee/batman.git
RUN git clone https://github.com/noojee/zone_di.dart.git

WORKDIR /src/batman

RUN mkdir /batman
RUN dart pub get
RUN dart compile exe /src/batman/bin/batman.dart -o /batman/batman


# Build minimal  image from AOT-compiled `/batman`
FROM build
COPY --from=build /batman/batman /batman/batman

WORKDIR /
RUN mkdir /etc/batman
WORKDIR /batman
RUN ./batman install --db_path=/data/hive --rule_path=/etc/batman/batman.yaml

# schedule scans.
ENTRYPOINT ["nice", "-n", "19", "./batman", "--quiet", "--no-colour", "cron","30 22 * * * *"]
