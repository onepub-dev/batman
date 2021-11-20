import 'package:dcli/dcli.dart';
import 'package:pci_file_monitor/src/log_source/source_analyser.dart';
import 'package:pci_file_monitor/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';
import '../rules.dart';
import '../selectors/selector.dart';

import 'log_source.dart';

/// Handles from Docker that have been sent to journald.
class DockerLogSource extends LogSource {
  static const String type = 'docker';

  @override
  String getType() => type;

  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  DockerLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    container = settings.ruleAsString(location, 'container', '');
    if (container.isEmpty) {
      throw RulesException(
          "The log_source $type MUST have a 'container' attribute");
    }
    trimPrefix = settings.ruleAsString(location, 'trimPrefix', '');
  }

  late final String container;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String? trimPrefix;

  @override
  Stream<String> stream() {
    return "journalctl CONTAINER_NAME=$container --since '1 day ago'".stream();
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
}
