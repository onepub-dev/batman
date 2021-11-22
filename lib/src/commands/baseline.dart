import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../log.dart';
import '../parsed_args.dart';
import '../rules.dart';
import '../scanner.dart';
import '../when.dart';

class BaselineCommand extends Command<void> {
  BaselineCommand();

  @override
  String get description =>
      'Scans the set of monitored directories and files creating a baseline hash for each entity.';

  @override
  String get name => 'baseline';

  @override
  void run() {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('You must be root to run a baseline'));
      exit(1);
    }

    if (!exists(Rules.pathToRules)) {
      logerr(red('''You must run 'batman install' first.'''));
      exit(1);
    }

    if (!ParsedArgs().secureMode) {
      log(orange(
          'Warning: you are running in insecure mode. Hash files can be modified by any user.'));
    }

    baseline(secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
  }

  static void baseline({required bool secureMode, required bool quiet}) {
    final rules = Rules.load(showWarnings: false);
    if (rules.entities.isEmpty) {
      log(red(
          'There were no entities in ${Rules.pathToRules}. Add at least one entity and try again'));
      log(red('$when baseline failed'));
      exit(1);
    }

    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() {
        log(blue('$when Deleting existing baseline'));

        if (exists(Rules.pathToHashes)) {
          deleteDir(Rules.pathToHashes, recursive: true);
        }

        scanner(_baselineFile,
            name: 'baseline', pathToInvalidFiles: alteredFiles);
      }, allowUnprivileged: true);
    });
  }

  /// Creates a baseline of the given file by creating
  /// a hash and saving the results in an identicial directory
  /// structure under .batman/baseline
  static int _baselineFile(
      {required Rules rules,
      required String entity,
      required String pathToInvalidFiles}) {
    final args = ParsedArgs();
    int fails = 0;
    if (!rules.excluded(entity)) {
      try {
        final hash = calculateHash(entity);
        final pathToHash = join(Rules.pathToHashes, entity.substring(1));
        final pathToHashDir = dirname(pathToHash);
        if (!exists(pathToHashDir)) createDir(pathToHashDir, recursive: true);

        /// stop anyone modifying the hash
        if (!args.secureMode) {
          pathToHash.write(hash.toString());
        } else {
          pathToHash.write(hash.toString());
          chown(pathToHash, user: 'root');

          /// only root can read/write
          /// group can read
          /// other has no access.
          chmod(640, pathToHash);
        }
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
