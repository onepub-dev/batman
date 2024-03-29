/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import 'commands/baseline.dart';
import 'commands/cli.dart';
import 'commands/cron.dart';
import 'commands/doctor.dart';
import 'commands/down.dart';
import 'commands/file.dart';
import 'commands/install.dart';
import 'commands/integrity.dart';
import 'commands/log.dart';
import 'commands/logs.dart';
import 'commands/up.dart';
import 'log.dart';
import 'version/version.g.dart';

class ParsedArgs {
  factory ParsedArgs() => _self;

  ParsedArgs.withArgs(this.args)
      : runner = CommandRunner<void>('batman', description) {
    _self = this;
    build();
    parse();
  }
  static late ParsedArgs _self;

  List<String> args;
  CommandRunner<void> runner;

  bool colour = true;
  bool quiet = false;
  late final bool secureMode;
  late final bool countMode;
  bool useLogfile = false;
  late final String logfile;

  void build() {
    runner.argParser
        .addFlag('verbose', abbr: 'v', help: 'Enable versbose logging');
    runner.argParser.addFlag('colour',
        abbr: 'c',
        defaultsTo: true,
        help:
            'Enabled colour coding of messages. You should disable colour when '
            'using the console to log.');
    runner.argParser.addOption('logfile',
        abbr: 'l', help: 'If set all output is sent to the provided logifile');
    runner.argParser.addFlag('insecure',
        help:
            'Should only be used during testing. When set, the hash files can be read/written by any user');
    runner.argParser.addFlag('quiet',
        abbr: 'q',
        help: "Don't output each directory scanned just log the totals and "
            'errors.');
    runner.argParser.addFlag('count',
        abbr: 't', help: "Don't output each directory scanned just a count.");

    runner.argParser.addFlag('version',
        help: 'Displays the batman version no. and exists.');
    runner
      ..addCommand(BaselineCommand())
      ..addCommand(CliCommand())
      ..addCommand(CronCommand())
      ..addCommand(DoctorCommand())
      ..addCommand(DownCommand())
      ..addCommand(FileCommand())
      ..addCommand(IntegrityCommand())
      ..addCommand(InstallCommand())
      ..addCommand(LogCommand())
      ..addCommand(LogsCommand())
      ..addCommand(UpCommand());
  }

  void parse() {
    late final ArgResults results;

    try {
      results = runner.argParser.parse(args);
    } on FormatException catch (e) {
      printerr(red(e.message));
      showUsage();
      throw ExitException(1);
    }
    Settings().setVerbose(enabled: results['verbose'] as bool);

    final version = results['version'] as bool == true;
    if (version == true) {
      print('batman $packageVersion');
      throw ExitException(0);
    }

    secureMode = results['insecure'] as bool == false;
    quiet = results['quiet'] as bool == true;
    countMode = results['count'] as bool == true;
    colour = results['colour'] as bool == true;

    if (results.wasParsed('logfile')) {
      useLogfile = true;
      logfile = results['logfile'] as String;
    } else {
      useLogfile = false;
    }
  }

  void showUsage() {
    print(runner.usage);
  }

  Future<void> run() async {
    try {
      await runner.run(args);
    } on FormatException catch (e) {
      logerr(red(e.message));
      showUsage();
      throw ExitException(1);
    } on UsageException catch (e) {
      logerr(red(e.message));
      showUsage();
      throw ExitException(1);
      // ignore: avoid_catches_without_on_clauses
    } catch (e, st) {
      logerr(red('''
$e
$st'''));
      throw ExitException(1);
    }
  }

  static final description = '''

${orange('System Integrity Monitor for PCI compliance of PCI DSS Requirement 11.5.')}

File Integrity Scanning:
  Run 'batman baseline' to create a baseline of your core system files.
  Run 'batman integrity' to check that none of the files in your baseline has changed.
  After doing a system upgrade you should re-baseline your system.

  PCI DSS 11.5 requires that a scan is run at least weekly, we recommend scheduling the scan to run daily.

Log Scanning
  Run 'batman logs' to scan you logs based on rules defined in ~/.batman/batman.yaml.
  See the README.md for details on setting up the log scanner.

You can alter the set of file system entities and log scanning rules  by modifying ~/.batman/batman.yaml''';
}

class ExitException implements Exception {
  ExitException(this.exitCode);

  int exitCode;
}
