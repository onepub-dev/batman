import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../dcli/resources/generated/resource_registry.g.dart';
import '../log.dart';

class InstallCommand extends Command<void> {
  InstallCommand() {
    argParser
      ..addMultiOption(name)
      ..addOption('db_path',
          abbr: 'p',
          help: 'Path to the store the db',
          defaultsTo: BatmanSettings.defaultPathToDb)
      ..addFlag('docker',
          hide: true,
          help: 'Pass this flag when install is running inside a '
              'docker conatiner');
  }
  @override
  String get description => 'Installs Batman.';

  @override
  String get name => 'install';

  @override
  void run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);

    final docker = argResults!['docker'] as bool;

    // prep path to rules
    final pathToBatman = dirname(BatmanSettings.pathToRules);
    if (!exists(pathToBatman)) {
      createDir(pathToBatman, recursive: true);
    }

    if (docker) {
      ResourceRegistry.resources['docker_rules.yaml']!
          .unpack(BatmanSettings.pathToRules);
    } else {
      ResourceRegistry.resources['local_rules.yaml']!
          .unpack(BatmanSettings.pathToRules);
    }

    BatmanSettings.load();

    // prep db path
    final pathToDb = argResults!['db_path'] as String;
    BatmanSettings().pathToDb = pathToDb;
    if (!exists(pathToDb)) {
      createDir(pathToDb, recursive: true);
    }

    /// hacky way to update rules
    replace(BatmanSettings.pathToRules, RegExp('  db_path:.*'),
        '  db_path: $pathToDb');

    log("Run 'batman baseline' to set an initial baseline");
    log("Schedule 'batman scan' to run at least weekly.");
    log(green('Installation complete.'));
  }
}
