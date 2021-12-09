import 'package:settings_yaml/settings_yaml.dart';

import '../batman_settings.dart';
import 'batman_yaml_logger.dart';
import 'rule.dart';

/// A reference (by name) to a rule
/// Used to connect a LogSource to a [Rule].
class RuleReference {
  RuleReference(this.rule, this.name);
  factory RuleReference.fromMap(SettingsYaml settings, String location) {
    final name = settings.selectAsString('$location.rule');

    if (name == null || name.isEmpty) {
      throw RulesException("Missing 'name' for rule at $location");
    }

    return RuleReference._internal(name);
  }

  RuleReference._internal(this.name) {
    BatmanYamlLogger().load(() => 'loaded rule reference: $name');
  }

  late final String name;

  late final Rule rule;
}
