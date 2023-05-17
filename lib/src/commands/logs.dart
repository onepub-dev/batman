/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:zone_di2/zone_di2.dart';

import '../batman_settings.dart';
import '../dependency_injection/tokens.dart';
import '../local_settings.dart';
import '../log.dart';
import '../log_scanner/scanner.dart';
import '../parsed_args.dart';
import '../when.dart';

/// Scans logs for problems.
class LogsCommand extends Command<void> {
  @override
  Future<int> run() async => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  Future<int> _run() async {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
       logerr(red('Error: You must be root to run a log scan'));
      return 1;
    }

    if (!exists(inject(localSettingsToken).rulePath)) {
       logerr(red('''Error: You must run 'batman install' first.'''));
      return 1;
    }

    if (!ParsedArgs().secureMode) {
       logwarn(
          '$when Warning: you are running in insecure mode. Not all files '
          'can be checked');
    }
    await logScan(
        secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    return 0;
  }

  @override
  String get description =>
      'Scans system logs looking for errors and malicious '
      'intent as defined in batman.yaml';

  @override
  String get name => 'logs';

  Future<void> logScan({required bool secureMode, required bool quiet}) async {
    withTempFile((alteredFiles) {
      Shell.current.withPrivileges(() async {
        final rules = BatmanSettings.load();
        final logSources = rules.logAudits;
        for (final source in logSources.sources) {
          if (source.exists) {
            await scanOneLog(name, null,
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
