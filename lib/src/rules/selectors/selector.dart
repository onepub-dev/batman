/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:meta/meta.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../enum_helper.dart';
import '../../settings_yaml_rules.dart';
import '../risk.dart';

export 'contains.dart';
export 'credit_card.dart';
export 'one_of.dart';

abstract class Selector {
  Selector.fromMap(SettingsYaml settings, String location,
      {Risk defaultRisk = Risk.critical, bool defaultTerminate = false}) {
    final type = settings.selectAsString('$location.type');
    if (type == null) {
      throw RulesException('Missing type for selector $location');
    }

    description = settings.ruleAsString(location, 'description', '');
    terminate = !settings.ruleAsBool(location, 'continue',
        defaultValue: !defaultTerminate);

    final riskName = settings.ruleAsString(
        location, 'risk', EnumHelper().getName(defaultRisk));

    try {
      risk = EnumHelper().getEnum(riskName, Risk.values);
    } on Exception catch (_) {
      throw RulesException("Invalid risk nane '$riskName' at $location. "
          'Choose one of ${Risk.values}');
    }
  }

  late final String description;

  /// If true and this [Selector] matches
  /// then stop processing selectors.
  /// true is the default.
  late final bool terminate;

  /// The risk level associated with lines selected
  late final Risk risk;

  String getType();

  /// Check if the [line] matches this [Selector]
  Selection matches(String line);

  @protected
  Selection selection({required bool matched}) {
    if (matched) {
      return terminate ? Selection.matchTerminate : Selection.matchContinue;
    } else {
      return Selection.nomatch;
    }
  }

  String sanitiseLine(String line) => line;

  /// returns a coloured code version of the
  /// description based on the Selectors risk
  /// level.
  String get heat {
    switch (risk) {
      case Risk.none:
        return description;
      case Risk.low:
        return blue(description);
      case Risk.medium:
        return yellow(description);
      case Risk.high:
        return orange(description);
      case Risk.critical:
        return red(description);
    }
  }
}

/// Controls how each [Selector]s match
/// results are handled.
enum Selection {
  /// the line is matched and no further selectors
  /// should be considered.
  matchTerminate,

  /// The line matched and further selectors
  /// should be considered.
  matchContinue,

  /// The line didn't match and further selectors
  /// should be considered.
  nomatch,
}
