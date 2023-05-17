/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dcli/docker.dart';
import 'package:zone_di2/zone_di2.dart';

import '../batman_settings.dart';
import '../dcli/resource/generated/resource_registry.g.dart';
import '../dependency_injection/tokens.dart';
import '../local_settings.dart';
import '../log.dart';

class InstallCommand extends Command<void> {
  InstallCommand() {
    argParser
      ..addOption('db_path',
          abbr: 'd',
          help: 'Path to the store the db',
          defaultsTo: BatmanSettings.defaultPathToDb)
      ..addFlag('overwrite', abbr: 'o', help: '''
If passed, even if the exiting config file exists they will be overwritten.
Normally the install will not replace an exiting rule file.''')
      ..addOption('rule_path', abbr: 'r', help: 'Path to the batman.yaml file');
  }
  @override
  String get description => 'Installs Batman.';

  @override
  String get name => 'install';

  @override
  int run() => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  int _run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);
    final overwrite = argResults!['overwrite'] as bool;

    final settings = inject(localSettingsToken);

    // check for a change to the batman.yaml path
    final pathToRuleYaml = argResults!['rule_path'] as String?;
    if (pathToRuleYaml != null) {
      if (!pathToRuleYaml.endsWith('batman.yaml')) {
        printerr(red('The --rule-path must end with "batman.yaml"'));
        return 1;
      }

      settings.rulePath = pathToRuleYaml;
      print('Saving rule_path to: ${settings.pathToLocalSettings}');
      settings.save();
    }

    // prep path to rules
    final pathToBatman = dirname(BatmanSettings.pathToSettingsDir);
    if (!exists(pathToBatman)) {
      createDir(pathToBatman, recursive: true);
    }

    final rulesFilename = settings.packedRuleYaml;
    if (!exists(settings.rulePath) || overwrite) {
      ResourceRegistry.resources[rulesFilename]!.unpack(settings.rulePath);
    }
    final dockerCompose =
        join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml');
    print('unpacking $dockerCompose');
    if (!exists(dockerCompose) || overwrite) {
      ResourceRegistry.resources['docker-compose.yaml']!.unpack(
          join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml'));
    }

    final pathToDockerFile =
        join(BatmanSettings.pathToSettingsDir, 'DockerFile');
    if (!exists(pathToDockerFile) || overwrite) {
      ResourceRegistry.resources['Dockerfile']!.unpack(pathToDockerFile);
    }

    BatmanSettings.load();

    // prep db path
    final pathToDb = argResults!['db_path'] as String;
    BatmanSettings().pathToDb = pathToDb;
    if (!exists(pathToDb)) {
      createDir(pathToDb, recursive: true);
    }

    /// hacky way to update rules
    replace(settings.rulePath, RegExp('  db_path:.*'), '  db_path: $pathToDb');

    log("Run 'batman baseline' to set an initial baseline");
    log("Schedule 'batman scan' to run at least weekly.");
    log(green('Installation complete.'));

    return 0;
  }

  Future<int> checkInstallation() async {
    final settings = inject(localSettingsToken);
    if (DockerShell.inDocker) {
      /// In a docker shell if the user mounts into /etc/batman (as advised)
      /// then the batman.yaml file won't exist so we need to create on
      /// first run.

      if (!exists(settings.rulePath)) {
        final rulesFilename = settings.packedRuleYaml;
        ResourceRegistry.resources[rulesFilename]!.unpack(settings.rulePath);
        print('Create batman.yaml in ${settings.rulePath}');
      }
    } else {
      if (!exists(settings.rulePath)) {
         logerr(red('''You must run 'batman install' first.'''));
        return 1;
      }
    }
    return 0;
  }
}
