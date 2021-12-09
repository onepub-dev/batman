import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../settings_yaml_rules.dart';
import 'docker_log_source.dart';
import 'file_log_source.dart';
import 'log_source.dart';
import 'njcontact_log_source.dart';

// ignore: avoid_classes_with_only_static_members
class LogSources {
  static LogSource fromMap(SettingsYaml settings, String location) {
    final type = settings.ruleAsString(location, 'type', '');

    if (type.isEmpty) {
      throw RulesException('Missing name for selector at $location');
    }

    if (type == DockerLogSource.type) {
      return DockerLogSource.fromMap(settings, location);
    } else if (type == FileLogSource.type) {
      return FileLogSource.fromMap(settings, location);
    } else if (type == NJContactLogSource.type) {
      return NJContactLogSource.fromMap(settings, location);
    } else {
      throw RulesException('Invalid LogSource type $type');
    }
  }
}
