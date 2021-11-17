import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:cron/cron.dart';
import 'package:dcli/dcli.dart';
import 'package:pci_file_monitor/src/commands/baseline.dart';

import '../rules.dart';
import 'scan.dart';

class CronCommand extends Command<void> {
  CronCommand() {
    argParser.addFlag('baseline', defaultsTo: false, help: '''
Runs the baseline on startup and then a scan based on the passed cron settings.''');

    argParser.addFlag('insecure',
        defaultsTo: false,
        help:
            'Should only be used during testing. When set, the hash files can be read/written by any user');
  }

  @override
  String get description => '''
Runs the scan on a schedule using standard crontab syntax.

The cron command is designed to allow you to run pcifim from a docker
container. You can either run the baseline outside the container or
use `pcifmi cron --baseline` to run a baseline each time the container starts
and then the regular scan as scheduled.

e.g. run the scan at 11:30pm each night.
    pcifmi cron '30   23  *   *   * '

If no arguments passed it is ran each not at 10:30 pm.
    ''';

  @override
  String get name => 'cron';

  @override
  void run() {
    bool secureMode = (argResults!['insecure'] as bool == false);
    bool baseline = (argResults!['baseline'] as bool == false);

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

    if (argResults!.rest.length > 1) {
      print(red(
          'The cron scheduled must be a single argument surrounded by quotes: e.g. pcifim cron "45 10 * * * "'));
      exit(1);
    }

    var scheduleArg = '30 22 * * * ';
    if (argResults!.rest.length == 1) {
      scheduleArg = argResults!.rest[0];
    }

    if (baseline) {
      BaselineCommand.baseline(secureMode: secureMode);
    }

    final Schedule schedule;
    try {
      schedule = Schedule.parse(scheduleArg);
    } on Exception {
      print(red('Failed to parse schedule: "$scheduleArg"'));
      exit(1);
    }

    Cron().schedule(schedule, () => ScanCommand.scan(secureMode: secureMode));
  }
}
