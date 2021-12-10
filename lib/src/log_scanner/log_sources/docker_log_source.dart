import 'package:dcli/dcli.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../settings_yaml_rules.dart';
import '../analysers/simple_analyser.dart';
import '../analysers/source_analyser.dart';
import 'log_source.dart';

/// Handles from Docker that have been sent to journald.
class DockerLogSource extends LogSource {
  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  DockerLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    container = settings.ruleAsString(location, 'container', '');
    if (container.isEmpty) {
      throw RulesException(
          "The log_source $type MUST have a 'container' attribute");
    }
    since = settings.ruleAsString(location, 'since', '');
    trimPrefix = settings.ruleAsString(location, 'trim_prefix', '');
  }
  static const String type = 'docker';

  @override
  String getType() => type;

  late final String container;
  late final String? since;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final String? trimPrefix;

  String? overridePath;

  @override
  Stream<String> stream() {
    if (overridePath == null) {
      return _command.stream();
    } else {
      return read(overridePath!).stream;
    }
  }

  String get _command {
    var command = 'journalctl CONTAINER_NAME=$container';
    if (since != null) {
      command += " --since '$since'";
    }
    return command;
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
  String get source => overridePath ?? _command;

  @override
  String preProcessLine(String line) => line;

  @override
  // ignore: avoid_setters_without_getters
  set overrideSource(String path) => overridePath = path;
}
