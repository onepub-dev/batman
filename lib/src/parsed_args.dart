import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:args/command_runner.dart';

import 'commands/baseline.dart';
import 'commands/install.dart';
import 'commands/scan.dart';

class ParsedArgs {
  ParsedArgs(this.args) : runner = CommandRunner<void>('pcifim', '''

${orange('File Integrity Monitor for PCI compliance of PCI DSS Requirement 11.5.')}

Run 'pcifim baseline' to create a baseline of your core system files.
Run 'pcifim scan' to check that none of the files in your baseline has changed.
After doing a system upgrade you should re-baseline your system.

PCI DSS 11.5 requires that a scan is run at least weekly, we recommend scheduling the scan to run daily.

You can alter the set of entities scanned by modifying ~/.pcifim/rules.yaml''') {
    build();
    parse();
  }

  List<String> args;
  CommandRunner<void> runner;

  void build() {
    runner.addCommand(BaselineCommand());
    runner.addCommand(ScanCommand());
    runner.addCommand(InstallCommand());
  }

  void parse() {}

  void showUsage() {
    runner.printUsage();
    exit(1);
  }

  void run() {
    try {
      waitForEx(runner.run(args));
    } on FormatException catch (e) {
      printerr(red(e.message));
      showUsage();
    }
  }
}
