import 'package:settings_yaml/settings_yaml.dart';

import 'batman_yaml_logger.dart';
import 'rule_reference.dart';

/// LogSources contain references to Rules
class RuleReferences {
  RuleReferences._internal(this.rules);

  RuleReferences.virtual(this.rules);

  factory RuleReferences.fromMap(SettingsYaml settings, String location) {
    final definitions = settings.selectAsList('$location.rules');

    if (definitions == null || definitions.isEmpty) {
      BatmanYamlLogger().warning(
          () => 'No rules for $location found in ${settings.filePath}');
    }
    final rules = <RuleReference>[];

    for (var i = 0; i < definitions!.length; i++) {
      final rule = RuleReference.fromMap(settings, '$location.rules.rule[$i]');
      rules.add(rule);
    }

    return RuleReferences._internal(rules);
  }
  final List<RuleReference> rules;
}
