import 'package:pci_file_monitor/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../rules.dart';
import 'selector.dart';

/// Checks if a log line has matches for all of
/// of the regex strings in [match].
/// After the regex matches if the [exclude]
/// also matches then the line will be excluded.
class RegEx extends Selector {
  static const String type = 'regex';

  /// To select the log line it must
  /// match on all of the items in [matche]
  late final List<RegExp> match;

  /// If [match] select the line
  /// then we check [exclude] to
  /// see if we should still ignore the line.
  late final List<RegExp> exclude;

  RegEx.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    final _match = settings.ruleAsStringList(location, 'match', <String>[]);
    if (_match.isEmpty) {
      throw RulesException(
          "The '$type' selector at $location requires a 'match' key");
    }
    for (final regex in _match) {
      match.add(RegExp(regex));
    }
    final _exclude = settings.ruleAsStringList(location, 'exclude', <String>[]);

    for (final regex in _exclude) {
      exclude.add(RegExp(regex));
    }
  }

  @override
  Selection matches(String line) {
    var matched = true;
    for (final oneof in match) {
      if (!oneof.hasMatch(line)) {
        matched = false;
        break;
      }
    }
    if (matched == true) {
      for (final oneof in exclude) {
        if (oneof.hasMatch(line)) {
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
