import 'package:settings_yaml/settings_yaml.dart';

import 'rules.dart';

extension SettingYamlRules on SettingsYaml {
  String ruleAsString(String location, String attribute, String defaultValue) {
    return tryRule(location, attribute, () {
          final value = selectAsString('$location.$attribute');
          if (value == null) {
            RuleLogger().info(() =>
                "The string attribute '$attribute for $location was not set");
          }
          return value;
        }) ??
        defaultValue;
  }

  bool ruleAsBool(String location, String attribute, bool defaultValue) {
    return tryRule(location, attribute, () {
          final value = selectAsBool('$location.$attribute');
          if (value == null) {
            RuleLogger().info(() =>
                "The bool attribute '$attribute for $location was not set");
          }
          return value;
        }) ??
        defaultValue;
  }

  int ruleAsInt(String location, String attribute, int defaultValue) {
    return tryRule(location, attribute, () {
          final value = selectAsInt('$location.$attribute');
          if (value == null) {
            RuleLogger().info(() =>
                "The int attribute '$attribute for $location was not set");
          }
          return value;
        }) ??
        defaultValue;
  }

  List<dynamic> ruleAsList(
      String location, String attribute, List<dynamic> defaultValue) {
    return tryRule(location, attribute, () {
          final value = selectAsList('$location.$attribute');
          if (value == null) {
            RuleLogger().info(() =>
                "The list attribute '$attribute for $location was not set");
          } else {
            if (value is! List) {
              throw RulesException(
                  "The '$attribute' attribute of the selector at $location must be a list");
            }
          }
          return value;
        }) ??
        defaultValue;
  }

  List<String> ruleAsStringList(
      String location, String attribute, List<String> defaultValue) {
    return tryRule(location, attribute, () {
          final result = <String>[];
          final value = selectAsList('$location.$attribute');
          if (value == null) {
            RuleLogger().info(() =>
                "The list attribute '$attribute for $location was not set");
          } else {
            for (final v in value) {
              result.add(v as String);
            }
            if (result is! List<String>) {
              throw RulesException(
                  "The '$attribute' attribute of the selector at $location must be a list");
            }
          }
          return result;
        }) ??
        defaultValue;
  }

  R? tryRule<R>(String location, String attribute, R? Function() getter) {
    try {
      return getter();
    } on PathNotFoundException catch (_) {
      RuleLogger()
          .info(() => 'The attribute $attribute at $location does not exist.');
    }
  }
}
