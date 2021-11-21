import 'package:dcli/dcli.dart';
import 'package:batman/src/log_source/source_analyser.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../selectors/selector.dart';
import '../settings_yaml_rules.dart';
import 'log_source.dart';

/// Handles logs from a text file
class NJContactLogSource extends LogSource {
  static const type = 'njcontact';
  static const startMessage = 'Starting Servlet engine';

  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  NJContactLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    container = 'njadmin';
    trimPrefix = settings.ruleAsString(location, 'trimPrefix', '');
  }

  late final String container;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String? trimPrefix;

  @override
  Stream<String> stream() {
    bool seenStart = false;

    /// filter log messages until we see the [startMessage]
    return "journalctl CONTAINER_NAME=$container --since '1 day ago'"
        .stream()
        .skipWhile((line) {
      if (seenStart) return false;
      if (line.contains(startMessage)) seenStart = true;
      return seenStart;
    });
  }

  @override
  String getKey(String line, Selector selector) {
    String? key;
    final match = RegExp('\\(.*?\\.java\\:.*?\\)').firstMatch(line);
    if (match != null) {
      key = match[0];
    }
    return key ?? selector.description;
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

  /// TODO is there a way to check if the journal file exists?
  @override
  bool get exists => true;

  @override
  // TODO: implement analyser
  SourceAnalyser get analyser => NJContactAnalyser();

  @override
  String getType() => type;
}

class NJContactAnalyser implements SourceAnalyser {
  var linesCounter = 0;

  bool resetRequired = false;

  @override
  void process(String line) {
    if (line.contains(NJContactLogSource.startMessage)) {
      resetRequired = true;
    }
  }

  @override
  bool get reset {
    final _reset = resetRequired;
    resetRequired = false;
    return _reset;
  }
}
