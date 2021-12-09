import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../../settings_yaml_rules.dart';
import 'selector.dart';

/// Checks if a log line contains all of
/// of the strings in [match]
class Contains extends Selector {
  Contains.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    match = settings.ruleAsStringList(location, 'match', <String>[]);

    if (match.isEmpty) {
      throw RulesException(
          "The 'contains' selector at $location requires a 'match' key");
    }
    exclude = settings.ruleAsStringList(location, 'exclude', <String>[]);
    insensitive =
        settings.ruleAsBool(location, 'insensitive', defaultValue: false);

    if (insensitive) {
      for (var i = 0; i < match.length; i++) {
        match[i] = match[i].toLowerCase();
      }
      for (var i = 0; i < exclude.length; i++) {
        exclude[i] = exclude[i].toLowerCase();
      }
    }
  }

  static const String type = 'contains';

  /// To select the log line it must
  /// match on all of the items in [match]
  late final List<String> match;

  /// If [match] select the line
  /// then we check [exclude] to
  /// see if we should still ignore the line.
  late final List<String> exclude;

  /// If true then we do a case insensative match
  late final bool insensitive;

  @override
  Selection matches(final String line) {
    var _line = line;
    if (insensitive) {
      _line = _line.toLowerCase();
    }
    var matched = true;
    for (final oneof in match) {
      if (!_line.contains(oneof)) {
        matched = false;
        break;
      }
    }
    if (matched == true) {
      for (final oneof in exclude) {
        if (_line.contains(oneof)) {
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
