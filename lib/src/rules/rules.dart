import 'package:collection/collection.dart';
import 'package:settings_yaml/settings_yaml.dart';

import 'batman_yaml_logger.dart';
import 'rule.dart';

class Rules {
  factory Rules.fromMap(SettingsYaml settings) {
    final definitions = settings.selectAsList('log_audits.rules');

    if (definitions == null || definitions.isEmpty) {
      BatmanYamlLogger()
          .warning(() => 'No rules found in ${settings.filePath}');
    }
    final rules = <Rule>[];

    for (var i = 0; i < definitions!.length; i++) {
      final rule = Rule.fromMap(settings, 'log_audits.rules.rule[$i]');
      rules.add(rule);
    }

    return Rules._internal(rules);
  }

  Rules._internal(this.rules);

  final List<Rule> rules;

  /// Find a rule by its name
  Rule? findByName(String ruleName) =>
      rules.firstWhereOrNull((rule) => rule.name == ruleName);
}
