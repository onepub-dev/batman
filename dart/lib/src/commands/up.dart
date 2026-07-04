/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:path/path.dart';
import 'package:zone_di2/zone_di2.dart';

import '../batman_settings.dart';
import '../dependency_injection/tokens.dart';
import '../local_settings.dart';

class UpCommand extends Command<void> {
  UpCommand() {
    argParser
      ..addOption('file', abbr: 'f', help: '''
Path to the docker-compose.yaml file
batman baseline --docker=batman --file=~/.batman/docker-compose.yaml
    ''')
      ..addFlag('detached',
          abbr: 'd', help: 'Start the container and detach from it.');
  }

  @override
  String get description => 'Starts the docker container';

  @override
  String get name => 'up';

  @override
  int run() => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  int _run() {
    final detached = argResults!['detached'] as bool;
    final detachedArg = detached ? '-d' : '';

    var file = argResults!['file'] as String?;
    var fileArg = '';
    file ??= join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml');
    if (!exists(file)) {
      printerr(red('The docker-compose file $file does not exist'));
      return 1;
    }
    fileArg = '-f $file';

    'docker-compose $fileArg up $detachedArg'.run;
    return 0;
  }
}
