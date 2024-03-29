/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:settings_yaml/settings_yaml.dart';

import 'rules/batman_yaml_logger.dart';

extension SettingYamlRules on SettingsYaml {
  String ruleAsString(String location, String attribute, String defaultValue) =>
      tryRule(location, attribute, () {
        final value = selectAsString('$location.$attribute');
        if (value == null) {
          BatmanYamlLogger().info(() =>
              "The string attribute '$attribute for $location was not set");
        }
        return value;
      }) ??
      defaultValue;

  bool ruleAsBool(String location, String attribute,
          {required bool defaultValue}) =>
      tryRule(location, attribute, () {
        final value = selectAsBool('$location.$attribute');
        if (value == null) {
          BatmanYamlLogger().info(
              () => "The bool attribute '$attribute for $location was not set");
        }
        return value;
      }) ??
      defaultValue;

  int ruleAsInt(String location, String attribute, int defaultValue) =>
      tryRule(location, attribute, () {
        final value = selectAsInt('$location.$attribute');
        if (value == null) {
          BatmanYamlLogger().info(
              () => "The int attribute '$attribute for $location was not set");
        }
        return value;
      }) ??
      defaultValue;

  List<dynamic> ruleAsList(
          String location, String attribute, List<dynamic> defaultValue) =>
      tryRule(location, attribute, () {
        final value = selectAsList('$location.$attribute');
        if (value == null) {
          BatmanYamlLogger().info(
              () => "The list attribute '$attribute for $location was not set");
        }
        return value;
      }) ??
      defaultValue;

  List<String> ruleAsStringList(
          String location, String attribute, List<String> defaultValue) =>
      tryRule(location, attribute, () {
        final result = <String>[];
        final value = selectAsList('$location.$attribute');
        if (value == null) {
          BatmanYamlLogger().info(
              () => "The list attribute '$attribute for $location was not set");
        } else {
          for (final v in value) {
            result.add(v as String);
          }
        }
        return result;
      }) ??
      defaultValue;

  R? tryRule<R>(String location, String attribute, R? Function() getter) {
    try {
      return getter();
    } on PathNotFoundException catch (_) {
      BatmanYamlLogger()
          .info(() => 'The attribute $attribute at $location does not exist.');
    }
    return null;
  }
}
