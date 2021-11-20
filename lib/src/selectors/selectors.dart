import 'package:settings_yaml/settings_yaml.dart';

import '../rules.dart';
import 'selector.dart';

class Selectors {
  // final _registry = <String, Selector>{};

  // void registry(String name, Selector selector) => _registry[name] = selector;

  // Selector? find(String name) => _registry[name];

  Selector fromMap(SettingsYaml settings, String location) {
    final type = settings.selectAsString('$location.type');

    if (type == null) {
      throw RulesException('Missing name for selector at $location');
    }

    if (type == CreditCard.type) {
      return CreditCard.fromMap(settings, location);
    } else if (type == Contains.type) {
      return Contains.fromMap(settings, location);
    } else if (type == OneOf.type) {
      return OneOf.fromMap(settings, location);
    } else {
      throw RulesException('Invalid selector type $type');
    }
  }
}
