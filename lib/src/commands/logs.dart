import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../log.dart';
import '../log_scanner/scanner.dart';
import '../parsed_args.dart';
import '../when.dart';

/// Scans logs for problems.
class LogsCommand extends Command<void> {
  @override
  void run() {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('Error: You must be root to run a log scan'));
      exit(1);
    }

    if (!exists(BatmanSettings.pathToRules)) {
      logerr(red('''Error: You must run 'batman install' first.'''));
      exit(1);
    }

    if (!ParsedArgs().secureMode) {
      log(orange(
          '$when Warning: you are running in insecure mode. Not all files '
          'can be checked'));
    }
    logScan(secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
  }

  @override
  String get description =>
      'Scans system logs looking for errors and malicious intent';

  @override
  String get name => 'logs';

  void logScan({required bool secureMode, required bool quiet}) {
    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() {
        final rules = BatmanSettings.load();
        final logSources = rules.logAudits;
        for (final source in logSources.sources) {
          if (source.exists) {
            scanOneLog(name, null,
                secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
          }
        }
      }, allowUnprivileged: true);

      if (!quiet) {
        log('');
      }
    });
  }
}
