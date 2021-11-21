import 'package:dcli/dcli.dart';
import 'package:dcli/dcli.dart' as dcli show exists;
import 'package:batman/src/log_source/source_analyser.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';
import '../rules.dart';
import '../selectors/selector.dart';

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
    exists;
    trimPrefix = settings.ruleAsString(location, 'trimPrefix', '');
  }

  late final String pathToLogFile;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String trimPrefix;

  @override
  Stream<String> stream() {
    return read(pathToLogFile).stream;
  }

  @override
  String getKey(String line, Selector selector) => selector.description;

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
      RuleLogger().warning(() =>
          'The auditable log file $pathToLogFile does not currently exist.');
    }
    return ready;
  }

  @override
  SourceAnalyser get analyser => NoopAnalyser();

  @override
  String getType() => type;

  @override
  String get source => pathToLogFile;
}
