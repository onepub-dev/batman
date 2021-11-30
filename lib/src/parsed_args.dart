import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:args/command_runner.dart';

import 'commands/baseline.dart';
import 'commands/cron.dart';
import 'commands/install.dart';
import 'commands/log.dart';
import 'commands/logs.dart';
import 'commands/rules.dart';
import 'commands/integrity.dart';
import 'log.dart';

class ParsedArgs {
  static late ParsedArgs _self;
  factory ParsedArgs() => _self;
  ParsedArgs.withArgs(this.args) : runner = CommandRunner<void>('batman', '''

${orange('System Integrity Monitor for PCI compliance of PCI DSS Requirement 11.5.')}

File Integrity Scanning:
  Run 'batman baseline' to create a baseline of your core system files.
  Run 'batman integrity' to check that none of the files in your baseline has changed.
  After doing a system upgrade you should re-baseline your system.

  PCI DSS 11.5 requires that a scan is run at least weekly, we recommend scheduling the scan to run daily.

Log Scanning
  Run 'batman logs' to scan you logs based on rules defined in ~/.batman/rules.yaml.
  See the README.md for details on setting up the log scanner.

You can alter the set of file system entities and log scanning rules  by modifying ~/.batman/rules.yaml''') {
    _self = this;
    build();
    parse();
  }

  List<String> args;
  CommandRunner<void> runner;

  late final bool colour;
  late final bool quiet;
  late final bool secureMode;
  late final bool useLogfile;
  late final String logfile;

  void build() {
    runner.argParser.addFlag('verbose',
        abbr: 'v', defaultsTo: false, help: 'Enable versbose logging');
    runner.argParser.addFlag('colour',
        abbr: 'c',
        defaultsTo: true,
        help:
            'Enabled colour coding of messages. You should disable colour when using the console to log.');
    runner.argParser.addOption('logfile',
        abbr: 'l', help: 'If set all output is sent to the provided logifile');
    runner.argParser.addFlag('insecure',
        defaultsTo: false,
        help:
            'Should only be used during testing. When set, the hash files can be read/written by any user');
    runner.argParser.addFlag('quiet',
        abbr: 'q',
        defaultsTo: false,
        help:
            "Don't output each directory scanned just log the totals and errors.");
    runner.addCommand(BaselineCommand());
    runner.addCommand(CronCommand());
    runner.addCommand(IntegrityCommand());
    runner.addCommand(InstallCommand());
    runner.addCommand(LogsCommand());
    runner.addCommand(LogCommand());
    runner.addCommand(RuleCheckCommand());
  }

  void parse() {
    var results = runner.argParser.parse(args);
    Settings().setVerbose(enabled: results['verbose'] as bool);

    secureMode = (results['insecure'] as bool == false);
    quiet = (results['quiet'] as bool == true);
    colour = (results['colour'] as bool == true);

    if (results.wasParsed('logfile')) {
      useLogfile = true;
      logfile = results['logfile'] as String;
    } else {
      useLogfile = false;
    }
  }

  void showUsage() {
    runner.printUsage();
    exit(1);
  }

  void run() {
    try {
      waitForEx(runner.run(args));
    } on FormatException catch (e) {
      logerr(red(e.message));
      showUsage();
    } on UsageException catch (e) {
      logerr(red(e.message));
      showUsage();
    }
  }
}
