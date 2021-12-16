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

class IntegrityCommand extends Command<void> {
  IntegrityCommand();

  @override
  String get description =>
      'Scans the set of monitored directories and files reporting any changes'
      ' since the last baseline.';

  @override
  String get name => 'integrity';

  @override
  int run() => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  int _run() {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr('Error: You must be root to run an integrity scan');
      return 1;
    }

    if (!exists(inject(localSettingsToken).rulePath)) {
      logerr('''Error: You must run 'batman install' first.''');
      return 1;
    }

    if (!ParsedArgs().secureMode) {
      logwarn(
          '$when Warning: you are running in insecure mode. Not all files can'
          ' be checked');
    }

    BatmanSettings.load();
    integrityScan(
        secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    return 0;
  }

  void integrityScan({required bool secureMode, required bool quiet}) {
    Shell.current.withPrivileges(() {
      withTempFile((alteredFiles) async {
        log('Marking baseline.');
        HiveStore().mark();

        scanner(_scanEntity,
            name: 'File Integrity Scan', pathToInvalidFiles: alteredFiles);

        log('Integrity scan complete.');
        log('Sweeping for deleted files.');
        _sweep(alteredFiles);
        log('No deleted files found.');

        /// Given we have just written every record twice (mark and sweep)
        /// Its time to compact the box.
        HiveStore().compact();
        await HiveStore().close();
      }, keep: true);
    }, allowUnprivileged: true);
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
            logwarn('$when $message');
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
          printerr(orange('is priviliged:  ${Shell.current.isPrivilegedUser}'));
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
