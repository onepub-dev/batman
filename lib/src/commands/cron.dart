/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';
import 'package:cron/cron.dart';
import 'package:dcli/dcli.dart';
import 'package:zone_di2/zone_di2.dart';

import '../dependency_injection/tokens.dart';
import '../local_settings.dart';
import '../log.dart';
import '../parsed_args.dart';
import 'baseline.dart';
import 'install.dart';
import 'integrity.dart';
import 'logs.dart';

class CronCommand extends Command<void> {
  CronCommand() {
    argParser
      ..addFlag('baseline', help: '''
Runs the baseline on startup and then a scan based on the passed cron settings.''')
      ..addFlag('integrity', defaultsTo: true, help: '''
Run the file integrity scan.''')
      ..addFlag('logs', defaultsTo: true, help: '''
Runs the log scan.''');
  }

  @override
  String get description => '''
Runs the File Integrity and Log scan on a schedule using standard crontab syntax.

The cron command is designed to allow you to run batman from a docker
container. You can either run the file integrity baseline outside the container or
use `batman cron --baseline` to run a baseline each time the container starts
and then the regular scan as scheduled.

By default both the File Integrity and Log scan is performed but you can disable
either using the --no-integrity and --no-logs flags.

e.g. run the scan at 11:30pm each night.
  batman cron '30   23  *   *   * '
    
If no arguments passed it is ran each not at 10:30 pm.

run just the file integrity scan a 1 am
  batman cron -no-logs '0   1  *   *   * '

run just the log scan a 10:15 am
  batman cron -no-integrity '15   10  *   *   * '



    ''';

  @override
  String get name => 'cron';

  @override
  Future<int> run() async => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  Future<int> _run() async {
    final baseline = argResults!['baseline'] as bool == true;
    final integrity = argResults!['integrity'] as bool == true;
    final logs = argResults!['logs'] as bool == true;

    if (logs == false && integrity == false) {
      logerr(red('You have disabled both scans. ' 'Enable one of the scans.'));
      return 1;
    }

    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('You must be root to run a scan'));
      return 1;
    }

    await InstallCommand().checkInstallation();

    if (!ParsedArgs().secureMode) {
      logwarn('Warning: you are running in insecure mode. '
          'Not all files can be checked');
    }

    if (argResults!.rest.length > 1) {
      log(red(
          'The cron scheduled must be a single argument surrounded by quotes: '
          'e.g. batman cron "0 45 10 * * *"'));
      return 1;
    }

    var scheduleArg = '0 30 22 * * *';
    if (argResults!.rest.length == 1) {
      scheduleArg = argResults!.rest[0];
    }
    if (baseline) {
      await BaselineCommand.baseline();
    }

    final Schedule schedule;
    try {
      schedule = Schedule.parse(scheduleArg);
    } on Exception catch (e) {
      log(red('Failed to parse schedule: "$scheduleArg" $e'));
      return 1;
    }
    // var now = DateTime.now();
    // log(schedule.shouldRunAt(DateTime(now.year, now.month
    //, now.day, 22, 30)));
    verbose(() =>
        'Schedule: seconds: ${schedule.seconds}, minutes: ${schedule.minutes}, '
        'hours: ${schedule.hours}, days: ${schedule.days},'
        ' weekdays: ${schedule.weekdays}, months: ${schedule.months}');

    print(green('Starting cron.'));
    Cron().schedule(
        schedule, () async => _runScans(integrity: integrity, logs: logs));
    return 0;
  }

  Future<void> _runScans({required bool integrity, required bool logs}) async {
    if (integrity) {
      log('Running scheduled Integrity Scan');
      await IntegrityCommand().integrityScan(
          secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    }
    if (logs) {
      log('Running scheduled Log Scan');
      await LogsCommand().logScan(
          secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    }
  }
}
