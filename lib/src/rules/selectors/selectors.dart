import 'package:batman/src/rules/selectors/regex.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import 'selector.dart';

class Selectors {
  // final _registry = <String, Selector>{};

  // void registry(String name, Selector selector) => _registry[name] = selector;

  // Selector? find(String name) => _registry[name];

  factory Selectors.fromMap(SettingsYaml settings, String location) {
    final selectorsLocation = '$location.selectors';

    final definitions = settings.selectAsList(selectorsLocation);
    final selectors = <Selector>[];
    if (definitions != null) {
      for (var i = 0; i < definitions.length; i++) {
        final selectorPath = '$selectorsLocation.selector[$i]';
        final type = settings.selectAsString('$selectorPath.type');

        if (type == null) {
          throw RulesException('Missing name for selector at $location');
        }

        if (type == CreditCard.type) {
          selectors.add(CreditCard.fromMap(settings, selectorPath));
        } else if (type == Contains.type) {
          selectors.add(Contains.fromMap(settings, selectorPath));
        } else if (type == OneOf.type) {
          selectors.add(OneOf.fromMap(settings, selectorPath));
        } else if (type == RegEx.type) {
          selectors.add(RegEx.fromMap(settings, selectorPath));
        } else {
          throw RulesException('Invalid selector type $type');
        }
      }
    }
    return Selectors._internal(selectors);
  }
  Selectors._internal(this.selectors);

  final List<Selector> selectors;
}
