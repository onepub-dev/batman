/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:settings_yaml/settings_yaml.dart';

import '../batman_settings.dart';
import '../settings_yaml_rules.dart';
import 'batman_yaml_logger.dart';
import 'selectors/selectors.dart';

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
    var _line = line;

    /// give each selector a chance to sanitize the line.
    for (final selector in selectors.selectors) {
      _line = selector.sanitiseLine(_line);
    }
    return _line;
  }

  late final String name;
  late final String description;
  late final Selectors selectors;
}
