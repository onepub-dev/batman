import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:cron/cron.dart';
import 'package:dcli/dcli.dart';
import 'package:pci_file_monitor/src/commands/baseline.dart';

import '../log.dart';
import '../parsed_args.dart';
import '../rules.dart';
import 'scan.dart';

class CronCommand extends Command<void> {
  CronCommand() {
    argParser.addFlag('baseline', defaultsTo: false, help: '''
Runs the baseline on startup and then a scan based on the passed cron settings.''');
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
    bool baseline = (argResults!['baseline'] as bool == true);

    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('You must be root to run a scan'));
      exit(1);
    }

    if (!exists(Rules.pathToRules)) {
      logerr(red('''You must run 'pcifim install' first.'''));
      exit(1);
    }

    if (!ParsedArgs().secureMode) {
      log(orange(
          'Warning: you are running in insecure mode. Not all files can be checked'));
    }

    if (argResults!.rest.length > 1) {
      log(red(
          'The cron scheduled must be a single argument surrounded by quotes: e.g. pcifim cron "45 10 * * * *"'));
      exit(1);
    }

    var scheduleArg = '30 22 * * * * *';
    if (argResults!.rest.length == 1) {
      scheduleArg = argResults!.rest[0];
    }
    if (baseline) {
      BaselineCommand.baseline(
          secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    }

    final Schedule schedule;
    try {
      schedule = Schedule.parse(scheduleArg);
    } on Exception {
      log(red('Failed to parse schedule: "$scheduleArg"'));
      exit(1);
    }
    // var now = DateTime.now();
    // log(schedule.shouldRunAt(DateTime(now.year, now.month, now.day, 22, 30)));
    verbose(() =>
        'Schedule: seconds: ${schedule.seconds}, minutes: ${schedule.minutes}, hours: ${schedule.hours}, days: ${schedule.days},'
        ' weekdays: ${schedule.weekdays}, months: ${schedule.months}');

    Cron().schedule(
        schedule,
        () => ScanCommand.scan(
            secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet));
  }
}
