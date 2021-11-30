import 'package:batman/src/rules/selectors/selectors.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../batman_settings.dart';
import 'batman_yaml_logger.dart';

class Rule {
  factory Rule.fromMap(
    SettingsYaml settings,
    String location,
  ) {
    final name = settings.ruleAsString(location, 'name', '');
    final description = settings.ruleAsString(location, 'description', '');

    if (name.isEmpty) {
      throw RulesException('Missing name for rule at $location');
    }

    final selectors = Selectors.fromMap(settings, location);

    return Rule._internal(name, description, selectors);
  }

  Rule._internal(this.name, this.description, this.selectors) {
    BatmanYamlLogger().load(() => 'loaded rule: $name, $description');
  }

  /// Over-ride this line if the rule needs to pre-process the
  /// contents of a matched line before it is added to the LogSource.
  /// This can be done used to remove sensitive data
  /// e.g. credit cards, passwords.
  String sanitiseLine(String line) {
    /// give each selector a chance to sanitize the line.
    for (final selector in selectors.selectors) {
      line = selector.sanitiseLine(line);
    }
    return line;
  }

  late final String name;
  late final String description;
  late final Selectors selectors;
}
