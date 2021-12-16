import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../local_settings.dart';
import '../log.dart';
import '../log_scanner/log_sources/file_log_source.dart';
import '../log_scanner/scanner.dart';
import '../parsed_args.dart';
import '../rules/rule_reference.dart';
import '../rules/rule_references.dart';
import '../rules/rules.dart';
import '../when.dart';

/// Scans logs for problems.
class LogCommand extends Command<void> {
  LogCommand() {
    argParser
      ..addOption('name', abbr: 'n', help: 'The name of the log_source to run')
      ..addOption('rule',
          abbr: 'r', help: 'The name of a rule to run over the given path')
      ..addOption('path',
          abbr: 'p', help: 'Alters the path that the log_source reads from.');
  }
  @override
  void run() {
    if (ParsedArgs().secureMode && !Shell.current.isPrivilegedProcess) {
      logerr(red('Error: You must be root to run a log scan'));
      exit(1);
    }

    if (!exists(LocalSettings().rulePath)) {
      logerr(red('''Error: You must run 'batman install' first.'''));
      exit(1);
    }

    if (!ParsedArgs().secureMode) {
      logwarn(
          '$when Warning: you are running in insecure mode. Not all files can'
          ' be checked');
    }

    final name = argResults!['name'] as String?;
    final path = argResults!['path'] as String?;
    final rule = argResults!['rule'] as String?;

    if (rule == null && name == null) {
      logerr('You must provide either --name or --rule');
      exit(1);
    }

    if (path != null) {
      if (!exists(path)) {
        logerr('The path ${truepath(path)} does not exist.');
        exit(1);
      }
    }

    if (rule != null) {
      if (path == null) {
        logerr('When you pass --rule you must also pass --path');
        exit(1);
      }
      _virtualScan(rule, path);
    } else {
      scanOneLog(name!, path,
          secureMode: ParsedArgs().secureMode, quiet: ParsedArgs().quiet);
    }
  }

  @override
  String get description => 'Scans a single log_source by name or path.';

  @override
  String get name => 'log';

  /// Scan a log file that isn't in the batman.yaml using rules
  /// from batman.yaml
  void _virtualScan(String ruleName, String pathToLogFile) {
    final rules = Rules.fromMap(BatmanSettings.load().settings);
    final rule = rules.findByName(ruleName);
    if (rule == null) {
      logerr(red('No rule with the name "$ruleName" exists'));
      exit(1);
    }

    final reference = RuleReference(rule, ruleName);
    final references = RuleReferences.virtual([reference]);

    final logSource = FileLogSource.virtual(references, pathToLogFile);
    scanLogSource(logSource: logSource, path: pathToLogFile);
  }
}
