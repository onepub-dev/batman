import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../rules.dart';

class BaselineCommand extends Command<void> {
  BaselineCommand() {
    argParser.addFlag('insecure',
        defaultsTo: false,
        help:
            'Should only be used during testing. When set, the hash files can be read/written by any user');
  }
  @override
  String get description =>
      'Scans the set of monitored directories and files creating a baseline hash for each entity.';

  @override
  String get name => 'baseline';

  @override
  void run() {
    bool secureMode = (argResults!['insecure'] as bool == false);

    if (secureMode && !Shell.current.isPrivilegedProcess) {
      printerr(red('You must be root to run a baseline'));
      exit(1);
    }

    if (!exists(Rules.pathToRules)) {
      printerr(red('''You must run 'pcifim install' first.'''));
      exit(1);
    }

    if (!secureMode) {
      print(orange(
          'Warning: you are running in insecure mode. Hash files can be modified by any user'));
    }

    baseline(secureMode: secureMode);
  }

  static void baseline({required bool secureMode}) {
    final rules = Rules.load();

    final exclusions = rules.exclusions;

    print(blue('Deleting existing baseline'));

    Shell.current.withPrivileges(() {
      if (exists(Rules.pathToHashes)) {
        deleteDir(Rules.pathToHashes, recursive: true);
      }

      print(blue('Running baseline'));
      var count = 0;
      for (final ruleEntity in rules.entities) {
        count = 0;
        print('');
        // print('Baselining: $entity');
        if (isDirectory(ruleEntity)) {
          find('*',
                  workingDirectory: ruleEntity,
                  types: [Find.directory, Find.file],
                  recursive: true)
              .forEach((entity) {
            if (isFile(entity)) {
              Terminal()
                  .overwriteLine('Baselining($count): $ruleEntity $entity ');
              _baselineFile(entity, exclusions, secureMode: secureMode);
              count++;
            }
          });
        } else {
          _baselineFile(ruleEntity, exclusions);
        }
      }
    }, allowUnprivileged: true);

    print('');
    print(blue(
        "baseline complete. Schedule 'pcifim scan' to run at least weekly."));
  }

  static bool excluded(List<String> exclusions, String entity) {
    for (final exclusion in exclusions) {
      if (entity.startsWith(exclusion)) {
        return true;
      }
    }
    return false;
  }

  /// Creates a baseline of the given file by creating
  /// a hash and saving the results in an identicial directory
  /// structure under .pcifim/baseline
  static void _baselineFile(String file, List<String> exclusions,
      {bool secureMode = true}) {
    if (!excluded(exclusions, file)) {
      try {
        final hash = calculateHash(file);
        final pathToHash = join(Rules.pathToHashes, file.substring(1));
        final pathToHashDir = dirname(pathToHash);
        if (!exists(pathToHashDir)) createDir(pathToHashDir, recursive: true);

        /// stop anyone modifying the hash
        if (!secureMode) {
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
        if (e.osError!.errorCode == 13 && !secureMode) {
          print('permission denied for $file, no hash calculated.');
        } else {
          printerr(red('${e.message} $file'));
        }
      }
    }
  }
}

class BaselineException implements Exception {
  BaselineException(this.message);
  String message;

  @override
  String toString() => message;
}
