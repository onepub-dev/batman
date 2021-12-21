import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:zone_di2/zone_di2.dart';

import '../batman_settings.dart';
import '../dependency_injection/tokens.dart';
import '../hive/hive_store.dart';
import '../hive/model/file_checksum.dart';
import '../local_settings.dart';
import '../log.dart';
import '../parsed_args.dart';
import '../scanner.dart';
import '../when.dart';
import 'install.dart';

class BaselineCommand extends Command<void> {
  BaselineCommand() {
    argParser
      ..addOption('docker', defaultsTo: 'batman', help: '''
Runs a baseline in an exiting batman docker container.
batman baseline --docker=batman
    ''')
      ..addOption('file', abbr: 'f', help: '''
Path to the docker-compose.yaml file
batman baseline --docker=batman --file=~/.batman/docker-compose.yaml
    ''');
  }

  @override
  String get description =>
      'Scans the set of monitored directories and files creating'
      ' a baseline hash for each entity.';

  @override
  String get name => 'baseline';

  @override
  int run() => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  int _run() {
    final container = argResults!['docker'] as String?;

    if (container == null) {
      if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
        logerr(red('You must be root to run a baseline'));
        return 1;
      }

      InstallCommand().checkInstallation();

      if (!ParsedArgs().secureMode) {
        logwarn('Warning: you are running in insecure mode. '
            'Hash files can be modified by any user.');
      }

      return baseline();
    } else {
      var file = argResults!['file'] as String?;
      var fileArg = '';
      file ??= join(BatmanSettings.pathToSettingsDir, 'docker-compose.yaml');
      if (!exists(file)) {
        printerr(red('The docker-compose file $file does not exist'));
        return 1;
      }
      fileArg = '-f $file';

      'docker-compose $fileArg run --entrypoint="/batman/batman baseline" $container'
          .run;
      return 0;
    }
  }

  static int baseline() {
    final settings = inject(localSettingsToken);
    final rules = BatmanSettings.load();
    log('Load rules from : ${settings.rulePath}');
    if (rules.entities.isEmpty) {
      log(red('There were no entities in ${settings.rulePath}. '
          'Add at least one entity and try again'));
      log(red('$when baseline failed'));
      return 1;
    }

    print(blue('Calculating Hashes'));
    print(blue('Typical processing time is 30sec per GB.'));

    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() {
        log(blue('$when Deleting existing baseline'));

        HiveStore().deleteBaseline();

        scanner(_baselineFile,
            name: 'File Integrity Baseline', pathToInvalidFiles: alteredFiles);
      }, allowUnprivileged: true);
    });
    return 0;
  }

  /// Creates a baseline of the given file by creating
  /// a hash and saving the results in an identicial directory
  /// structure under .batman/baseline
  static int _baselineFile(
      {required BatmanSettings rules,
      required String entity,
      required String pathToInvalidFiles}) {
    final args = ParsedArgs();
    var fails = 0;
    try {
      // final hash = calculateHash(entity);
      final hash = FileChecksum.contentChecksum(entity);
      // make entity path relative by removing leading slash
      // final pathToHashDir = dirname(pathToHash);

      HiveStore().addChecksum(entity, hash);
      // if (!exists(pathToHashDir)) createDir(pathToHashDir,
      //recursive: true);

      // /// stop anyone modifying the hash
      // if (!args.secureMode) {
      //   pathToHash.write(hash.toString());
      // } else {
      //   pathToHash.write(hash.toString());
      //   // chown(pathToHash, user: 'root');

      //   // /// only root can read/write
      //   // /// group can read
      //   // /// other has no access.
      //   // chmod(640, pathToHash);
      // }
    } on FileSystemException catch (e) {
      if (e.osError!.errorCode == 13 && !args.secureMode) {
        final message =
            'Warning: permission denied for $entity, no hash calculated.';
        log(red('$when $message'));
        pathToInvalidFiles.append(message);
        fails++;
      } else {
        final message = '${e.message} $entity';
        logerr(red('$when $message'));
        pathToInvalidFiles.append(message);
      }
    }
    return fails;
  }
}

class BaselineException implements Exception {
  BaselineException(this.message);
  String message;

  @override
  String toString() => message;
}
