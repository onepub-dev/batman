import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dcli/docker.dart';

import '../batman_settings.dart';
import '../dcli/resource/generated/resource_registry.g.dart';
import '../local_settings.dart';
import '../log.dart';

class InstallCommand extends Command<void> {
  InstallCommand() {
    argParser
      ..addOption('db_path',
          abbr: 'd',
          help: 'Path to the store the db',
          defaultsTo: BatmanSettings.defaultPathToDb)
      ..addOption('rule_path', abbr: 'r', help: 'Path to the batman.yaml file');
  }
  @override
  String get description => 'Installs Batman.';

  @override
  String get name => 'install';

  @override
  void run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);

    // check for a change to the batman.yaml path
    final pathToRuleYaml = argResults!['rule_path'] as String?;
    if (pathToRuleYaml != null) {
      if (!pathToRuleYaml.endsWith('batman.yaml')) {
        printerr(red('The --rule-path must end with "batman.yaml"'));
        exit(1);
      }
      final settings = LocalSettings.load()..rulePath = pathToRuleYaml;
      print('Saving rule_path to: ${LocalSettings.pathToLocalSettings}');
      settings.save();
    }

    // prep path to rules
    final pathToBatman = dirname(BatmanSettings.pathToSettingsDir);
    if (!exists(pathToBatman)) {
      createDir(pathToBatman, recursive: true);
    }

    final rulesFilename = LocalSettings().packedRuleYaml;
    ResourceRegistry.resources[rulesFilename]!.unpack(LocalSettings().rulePath);
    print('unpacking '
        '${join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml')}');
    ResourceRegistry.resources['docker-compose.yaml']!
        .unpack(join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml'));
    ResourceRegistry.resources['Dockerfile']!
        .unpack(join(BatmanSettings.pathToSettingsDir, 'DockerFile'));

    BatmanSettings.load();

    // prep db path
    final pathToDb = argResults!['db_path'] as String;
    BatmanSettings().pathToDb = pathToDb;
    if (!exists(pathToDb)) {
      createDir(pathToDb, recursive: true);
    }

    /// hacky way to update rules
    replace(LocalSettings().rulePath, RegExp('  db_path:.*'),
        '  db_path: $pathToDb');

    log("Run 'batman baseline' to set an initial baseline");
    log("Schedule 'batman scan' to run at least weekly.");
    log(green('Installation complete.'));
  }

  void checkInstallation() {
    if (DockerShell.inDocker) {
      /// In a docker shell if the user mounts into /etc/batman (as advised)
      /// then the batman.yaml file won't exist so we need to create on
      /// first run.
      if (!exists(LocalSettings().rulePath)) {
        final rulesFilename = LocalSettings().packedRuleYaml;
        ResourceRegistry.resources[rulesFilename]!
            .unpack(LocalSettings().rulePath);
        print('Create batman.yaml in ${LocalSettings().rulePath}');
      }
    } else {
      if (!exists(LocalSettings().rulePath)) {
        logerr(red('''You must run 'batman install' first.'''));
        exit(1);
      }
    }
  }
}
