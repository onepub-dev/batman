import 'package:batman/src/log_scanner/analysers/simple_analyser.dart';
import 'package:batman/src/rules/batman_yaml_logger.dart';
import 'package:batman/src/rules/rule_references.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:dcli/dcli.dart';
import 'package:dcli/dcli.dart' as dcli show exists;
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../log.dart';
import '../analysers/source_analyser.dart';
import 'log_source.dart';

/// Handles logs from a text file
class FileLogSource extends LogSource {
  static const String type = 'file';

  /// Creates a LogSource that reads from a log file
  /// returning any log messages form the passed docker container.
  FileLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    pathToLogFile = settings.ruleAsString(location, 'path', '');
    if (pathToLogFile.isEmpty) {
      throw RulesException(
          "The log_source $location is missing a 'path' attribute.");
    }

    /// log a warning if the file doesn't exist.
    if (!dcli.exists(pathToLogFile)) {
      logwarn(
          "The path ${truepath(pathToLogFile)} for log_source: $name doesn't exists");
    }

    trimPrefix = settings.ruleAsString(location, 'trim_prefix', '');
  }

  /// Creates a LogSource that reads from a log file
  /// returning any log messages form the passed docker container.
  FileLogSource.virtual(RuleReferences references, String pathToLogFile)
      : super.virtual(name: 'Virtual', ruleReferences: references) {
    trimPrefix = '';
  }

  late final String pathToLogFile;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String trimPrefix;

  String? overridePath;

  @override
  Stream<String> stream() {
    if (overridePath == null) {
      return read(pathToLogFile).stream;
    } else {
      return read(overridePath!).stream;
    }
  }

  @override
  String tidyLine(String line) {
    var idx = line.indexOf(trimPrefix);
    if (idx < 0) {
      idx = 0;
    }

    return line.substring(idx);
  }

  @override
  bool get exists {
    var ready = dcli.exists(pathToLogFile);
    if (!ready) {
      BatmanYamlLogger().warning(() =>
          'The auditable log file $pathToLogFile does not currently exist.');
    }
    return ready;
  }

  @override
  SourceAnalyser get analyser => SimpleSourceAnalyser();

  @override
  String getType() => type;

  @override
  String get source => overridePath ?? pathToLogFile;

  @override
  String preProcessLine(String line) => line;

  @override
  set overrideSource(String path) => overridePath = path;
}
