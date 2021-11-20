import 'package:pci_file_monitor/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../rules.dart';
import 'selector.dart';

/// Excludes log lines from consideration.
/// if the strings in [match]
class Exclude extends Selector {
  static const String type = 'exclude';

  /// To select the log line it must
  /// match on all of the items in [matche]
  late final List<String> match;

  /// If [match] select the line
  /// then we check [exclude] to
  /// see if we should still ignore the line.
  late final List<String> exclude;

  Exclude.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    match = settings.ruleAsStringList(location, 'match', <String>[]);
    if (match.isEmpty) {
      throw RulesException(
          "The 'exclude' selector at $location requires a 'match' key");
    }
    exclude = settings.ruleAsStringList(location, 'exclude', <String>[]);
  }

  @override
  Selection matches(String line) {
    var matched = false;
    for (final oneof in match) {
      if (line.contains(oneof)) {
        matched = true;
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
