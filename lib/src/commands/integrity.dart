import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../log.dart';
import '../parsed_args.dart';
import '../batman_settings.dart';
import '../scanner.dart';
import '../when.dart';

class IntegrityCommand extends Command<void> {
  IntegrityCommand();

  @override
  String get description =>
      'Scans the set of monitored directories and files reporting any changes since the last baseline.';

  @override
  String get name => 'integrity';

  @override
  void run() {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('Error: You must be root to run an integrity scan'));
      exit(1);
    }

    if (!exists(BatmanSettings.pathToRules)) {
      logerr(red('''Error: You must run 'batman install' first.'''));
      exit(1);
    }

    if (!ParsedArgs().secureMode) {
      log(orange(
          '$when Warning: you are running in insecure mode. Not all files can be checked'));
    }
    integrityScan(
        secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
  }

  void integrityScan({required bool secureMode, required bool quiet}) {
    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() {
        scanner(_scanEntity,
            name: 'File Integrity Scan', pathToInvalidFiles: alteredFiles);
      }, allowUnprivileged: true);

      if (!quiet) {
        log('');
      }
    });
  }

  /// Creates a baseline of the given file by creating
  /// a hash and saving the results in an identicial directory
  /// structure under .batman/baseline
  static int _scanEntity(
      {required BatmanSettings rules,
      required String entity,
      required String pathToInvalidFiles}) {
    int failed = 0;
    if (!rules.excluded(entity)) {
      try {
        final scanHash = calculateHash(entity);

        final pathToHash =
            join(BatmanSettings.pathToHashes, entity.substring(1));

        final baselineHash =
            DigestHelper.hexDecode(read(pathToHash).firstLine!);

        if (scanHash != baselineHash) {
          failed = 1;
          final message = 'Integrity: Detected altered file: $entity';
          logerr(red('$when $message'));
          pathToInvalidFiles.append(message);
        }
      } on ReadException catch (_) {
        failed = 1;
        final message = 'Integrity: New file created since baseline: $entity';
        log(orange('$when $message'));
        pathToInvalidFiles.append(message);
      } on FileSystemException catch (e) {
        if (e.osError!.errorCode == 13 && !ParsedArgs().secureMode) {
          final message =
              'Error: permission denied for $entity, no hash calculated.';
          log('$when $message');
          pathToInvalidFiles.append(message);
        } else {
          final message = '${e.message} $entity';
          logerr(red('$when $message'));
          pathToInvalidFiles.append(message);
        }
      }
    }
    return failed;
  }
}
