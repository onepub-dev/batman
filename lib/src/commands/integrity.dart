import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../hive/hive_store.dart';
import '../hive/model/file_checksum.dart';
import '../log.dart';
import '../parsed_args.dart';
import '../scanner.dart';
import '../when.dart';

class IntegrityCommand extends Command<void> {
  IntegrityCommand();

  @override
  String get description =>
      'Scans the set of monitored directories and files reporting any changes'
      ' since the last baseline.';

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
          '$when Warning: you are running in insecure mode. Not all files can'
          ' be checked'));
    }

    BatmanSettings.load();
    integrityScan(
        secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
  }

  void integrityScan({required bool secureMode, required bool quiet}) {
    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() {
        log('Marking baseline');

        HiveStore().mark();
        log('Scanning for changes');
        scanner(_scanEntity,
            name: 'File Integrity Scan', pathToInvalidFiles: alteredFiles);
      }, allowUnprivileged: true);

      if (!quiet) {
        log('');
      }

      log('Sweeping for deleted files');
      _sweep(alteredFiles);

      /// Given we have just written every record twice (mark and sweep)
      /// Its time to compact the box.
      HiveStore().compact();
    });
  }

  /// Creates a baseline of the given file by creating
  /// a hash and saving the results in an identicial directory
  /// structure under .batman/baseline
  static int _scanEntity(
      {required BatmanSettings rules,
      required String entity,
      required String pathToInvalidFiles}) {
    var failed = 0;
    if (!rules.excluded(entity)) {
      try {
        final hash = FileChecksum.contentChecksum(entity);

        final result = HiveStore().compareCheckSum(entity, hash, clear: true);
        switch (result) {
          case CheckSumCompareResult.mismatch:
            failed = 1;
            final message = 'Integrity: Detected altered file: $entity';
            logerr(red('$when $message'));
            pathToInvalidFiles.append(message);
            break;
          case CheckSumCompareResult.missing:
            failed = 1;
            final message =
                'Integrity: New file created since baseline: $entity';
            log(orange('$when $message'));
            pathToInvalidFiles.append(message);
            break;
          case CheckSumCompareResult.matching:
            // no action required.
            break;
        }
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

  /// We marked all files in hive db at the start
  /// We no check for any that didn't get cleared.
  /// If a file didn't get cleared than it was deleted
  /// since the baseline.
  void _sweep(String pathToInvalidFiles) {
    waitForEx(_sweepAsync(pathToInvalidFiles));
  }

  Future<void> _sweepAsync(String pathToInvalidFiles) async {
    await for (final path in HiveStore().sweep()) {
      final message = 'Error: file deleted  $path';
      logerr(red('$when $message'));
      pathToInvalidFiles.append(message);
    }
  }
}
