import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import 'log_source.dart';

abstract class GroupedLogSource extends LogSource {
  /// Controls how many errors from this log source we output
  //late final int top;
  GroupedLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    final groupBy = settings.ruleAsString(location, 'group_by', '');
    this.groupBy = groupBy.isNotEmpty ? RegExp(groupBy) : null;
  }

  late final RegExp? groupBy;
}
