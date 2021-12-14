#! /usr/bin/env dcli

import 'dart:io';

import 'package:batman/src/version/version.g.dart';
import 'package:dcli/dcli.dart';
import 'package:dcli_scripts/dcli_scripts.dart';

/// Builds a docker container for local dev testing.

void main(List<String> args) {
  final parser = ArgParser()
    ..addFlag('fresh', help: 'Force a fresh copy of the source')
    ..addFlag('up', help: 'Run the container without building')
    ..addFlag('down', help: 'Shut a detached container down')
    ..addFlag('cli',
        help: 'Run the container in detached mode and then '
            'enter the container')
    ..addFlag('help', defaultsTo: false, help: 'Displays this help message');

  late final ArgResults results;
  try {
    results = parser.parse(args);
  } on FormatException catch (e) {
    printerr(red(e.message));
    exit(1);
  }

  final help = results['help'] as bool;
  if (help) {
    print(parser.usage);
    exit(1);
  }
  final fresh = results['fresh'] as bool;
  final up = results['up'] as bool;
  final cli = results['cli'] as bool;
  final down = results['down'] as bool;

  if (cli && up) {
    printerr(red('You can only use one of --cli and --run'));
  }

  final projectRoot = DartProject.self.pathToProjectRoot;
  final dockerfilePath = join(projectRoot, 'docker', 'Dockerfile.dev');

  final tag = 'test/batman:$packageVersion';
  const latest = 'test/batman:latest';
  const container = 'batman_dev';

  if (down) {
    'docker-compose -f resource/docker-compose.dev.yaml down'.run;
    exit(1);
  }

  if (!up && !cli) {
    dockerPublish(
        pathToDockerFile: dockerfilePath,
        repository: 'test',
        clone: fresh,
        push: false,
        confirm: false);
    'docker  build -t $tag -t $latest -f $dockerfilePath .'.run;
    'docker-compose -f resource/docker-compose.dev.yaml up -d'.run;
  }

  if (up) {
    'docker-compose -f resource/docker-compose.dev.yaml up'.run;
  }

  if (cli) {
    'docker-compose -f resource/docker-compose.dev.yaml up -d'.run;
    print('hi');
    'docker exec -it $container /bin/bash'.run;
  }
}
