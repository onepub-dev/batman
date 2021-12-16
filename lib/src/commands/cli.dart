import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';

class CliCommand extends Command<void> {
  CliCommand() {
    argParser.addOption('file', abbr: 'f', help: '''
Path to the docker-compose.yaml file
batman baseline --docker=batman --file=~/.batman/docker-compose.yaml
    ''');
  }

  @override
  String get description =>
      'Start the batman docker container and connects to the cli.';

  @override
  String get name => 'cli';

  @override
  void run() {
    var file = argResults!['file'] as String?;
    var fileArg = '';
    file ??= join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml');
    if (!exists(file)) {
      printerr(red('The docker-compose file $file does not exist'));
      exit(1);
    }
    fileArg = '-f $file';

    'docker-compose $fileArg up -d'.run;
    print(green('Entering batman container'));

    final result =
        'docker exec -it batman /bin/bash'.start(nothrow: true, terminal: true);
    if (result.exitCode != 127) {
      printerr(red(result.toParagraph()));
    }
  }
}
