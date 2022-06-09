/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../settings_yaml_rules.dart';
import '../analysers/simple_analyser.dart';
import '../analysers/source_analyser.dart';
import 'log_source.dart';

/// Handles from Docker that have been sent to journald.
class JournalCtlSource extends LogSource {
  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  JournalCtlSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    args = settings.ruleAsString(location, 'args', '');
    trimPrefix = settings.ruleAsString(location, 'trim_prefix', '');
  }
  static const String type = 'journalctl';

  @override
  String getType() => type;

  late final String args;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String? trimPrefix;

  String? overridePath;

  @override
  Stream<String> stream() {
    if (overridePath == null) {
      return 'journalctl $args'.stream();
    } else {
      return read(overridePath!).stream;
    }
  }

  @override
  String tidyLine(String line) {
    var idx = 0;
    if (trimPrefix != null) {
      idx = line.indexOf(trimPrefix!);
      if (idx < 0) {
        idx = 0;
      }
    }

    return line.substring(idx);
  }

  @override

  /// TODO(bsutton): is there a way to check if the journal file exists?
  bool get exists => true;

  @override
  SourceAnalyser get analyser => SimpleSourceAnalyser();

  @override
  String get source => overridePath ?? 'journalctl $args';

  @override
  String preProcessLine(String line) => line;

  @override
  // ignore: avoid_setters_without_getters
  set overrideSource(String path) => overridePath = path;
}
