/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';
import 'package:dcli/dcli.dart' as dcli show exists;
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../rules/batman_yaml_logger.dart';
import '../../rules/rule_references.dart';
import '../../settings_yaml_rules.dart';
import '../analysers/simple_analyser.dart';
import '../analysers/source_analyser.dart';
import 'log_source.dart';

/// Handles logs from a text file
class FileLogSource extends LogSource {
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
      BatmanYamlLogger()
          .warning(() => 'The path ${truepath(pathToLogFile)} for log_source: '
              "$name doesn't exist");
    }

    trimPrefix = settings.ruleAsString(location, 'trim_prefix', '');
  }

  /// Creates a LogSource that reads from a log file
  /// returning any log messages form the passed docker container.
  FileLogSource.virtual(RuleReferences references, this.pathToLogFile)
      : super.virtual(name: 'Virtual', ruleReferences: references) {
    trimPrefix = '';
  }

  static const String type = 'file';
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
    final ready = dcli.exists(pathToLogFile);
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
  // ignore: avoid_setters_without_getters
  set overrideSource(String path) => overridePath = path;
}
