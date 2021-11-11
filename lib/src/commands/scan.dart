import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../rules.dart';

class ScanCommand extends Command<void> {
  ScanCommand() {
    argParser.addFlag('insecure',
        defaultsTo: false,
        help:
            'Should only be used during testing. When set the hash files can be read/written by any user');
  }

  @override
  String get description =>
      'Scans the set of monitored directories and files reporting any changes since the last baseline.';

  @override
  String get name => 'scan';

  @override
  void run() {
    bool secureMode = (argResults!['insecure'] as bool == false);

    if (secureMode && !Shell.current.isPrivilegedProcess) {
      printerr(red('You must be root to run a scan'));
      exit(1);
    }

    if (!exists(Rules.pathToRules)) {
      printerr(red('''You must run 'pcifim install' first.'''));
      exit(1);
    }

    if (!secureMode) {
      print(orange(
          'Warning: you are running in insecure mode. Not all files can be checked'));
    }
    final rules = Rules.load();

    final exclusions = rules.exclusions;

    var count = 0;
    var failed = 0;

    Shell.current.withPrivileges(() {
      for (final ruleEntity in rules.entities) {
        count = 0;
        print('');
        if (isDirectory(ruleEntity)) {
          find('*',
                  workingDirectory: ruleEntity,
                  types: [Find.directory, Find.file],
                  recursive: true)
              .forEach((entity) {
            if (isFile(entity)) {
              Terminal()
                  .overwriteLine('Scanning($count): $ruleEntity $entity ');

              failed += scan(entity, exclusions, secureMode: secureMode);
              count++;
            }
          });
        } else {
          failed += scan(ruleEntity, exclusions, secureMode: secureMode);
        }
      }
    });
    print('');
    if (failed > 0) {
      print(red("scan complete. $failed altered files found!"));
    } else {
      print(green("scan complete. No errors"));
    }
  }

  bool excluded(List<String> exclusions, String entity) {
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
  int scan(String file, List<String> exclusions, {required bool secureMode}) {
    int failed = 0;
    if (!excluded(exclusions, file)) {
      try {
        final scanHash = calculateHash(file);

        final pathToHash = join(Rules.pathToHashes, file.substring(1));

        final baselineHash =
            DigestHelper.hexDecode(read(pathToHash).firstLine!);

        if (scanHash != baselineHash) {
          failed = 1;
          printerr(red('Detected altered file: $file'));
        }
      } on ReadException catch (_) {
        failed = 1;
        print(orange('New file created since baseline: $file'));
      } on FileSystemException catch (e) {
        if (e.osError!.errorCode == 13 && !secureMode) {
          print('permission denied for $file, no hash calculated.');
        } else {
          printerr(red('${e.message} $file'));
        }
      }
    }
    return failed;
  }
}

class ScanException implements Exception {
  ScanException(this.message);
  String message;
}
