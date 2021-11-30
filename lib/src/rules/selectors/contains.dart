import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import 'selector.dart';

/// Checks if a log line contains all of
/// of the strings in [match]
class Contains extends Selector {
  static const String type = 'contains';

  /// To select the log line it must
  /// match on all of the items in [matche]
  late final List<String> match;

  /// If [match] select the line
  /// then we check [exclude] to
  /// see if we should still ignore the line.
  late final List<String> exclude;

  /// If true then we do a case insensative match
  late final bool insensitive;

  Contains.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    match = settings.ruleAsStringList(location, 'match', <String>[]);

    if (match.isEmpty) {
      throw RulesException(
          "The 'contains' selector at $location requires a 'match' key");
    }
    exclude = settings.ruleAsStringList(location, 'exclude', <String>[]);
    insensitive = settings.ruleAsBool(location, 'insensitive', false);

    if (insensitive) {
      for (int i = 0; i < match.length; i++) {
        match[i] = match[i].toLowerCase();
      }
      for (int i = 0; i < exclude.length; i++) {
        exclude[i] = exclude[i].toLowerCase();
      }
    }
  }

  @override
  Selection matches(String line) {
    if (insensitive) {
      line = line.toLowerCase();
    }
    var matched = true;
    for (final oneof in match) {
      if (!line.contains(oneof)) {
        matched = false;
        break;
      }
    }
    if (matched == true) {
      for (final oneof in exclude) {
        if (line.contains(oneof)) {
          matched = false;
          break;
        }
      }
    }
    return selection(matched: matched);
  }

  @override
  String getType() => type;
}
