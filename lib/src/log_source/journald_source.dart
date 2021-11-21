import 'package:dcli/dcli.dart';
import 'package:batman/src/log_source/source_analyser.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';
import '../rules.dart';
import '../selectors/selector.dart';

import 'log_source.dart';

/// Handles from Docker that have been sent to journald.
class JournaldSource extends LogSource {
  static const String type = 'journald';

  @override
  String getType() => type;

  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  JournaldSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    filter = settings.ruleAsString(location, 'filter', '');
    if (filter.isEmpty) {
      throw RulesException(
          "The log_source $type MUST have a 'filter' attribute");
    }
    trimPrefix = settings.ruleAsString(location, 'trimPrefix', '');
  }

  late final String filter;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String? trimPrefix;

  @override
  Stream<String> stream() {
    return "journalctl $filter --since '1 day ago'".stream();
  }

  @override
  String getKey(String line, Selector selector) => selector.description;

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

  /// TODO is there a way to check if the journal file exists?
  bool get exists => true;

  @override
  SourceAnalyser get analyser => NoopAnalyser();

  @override
  String get source => filter;
}
