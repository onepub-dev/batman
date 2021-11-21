import 'package:batman/src/selectors/selectors.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../selectors/selector.dart';
import 'source_analyser.dart';

abstract class LogSource {
  /// Controls how many errors from this log source we output
  //late final int top;
  LogSource.fromMap(SettingsYaml settings, String location) {
    top = settings.ruleAsInt(location, 'top', 1000);
    description =
        settings.ruleAsString(location, 'description', 'not supplied');

    final _selectors = settings.ruleAsList(location, 'selectors', <String>[]);
    for (var i = 0; i < _selectors.length; i++) {
      selectors.add(
          Selectors().fromMap(settings, '$location.selectors.selector[$i]'));
    }
  }

  late final int top;
  late final String description;

  final selectors = <Selector>[];

  bool get exists;

  SourceAnalyser get analyser;

  String getType();

  Stream<String> stream();

  /// Returns a key as a method to link
  /// lines selected out of log source
  /// as being important.
  String getKey(String line, Selector selector);

  /// Allows the source to tidy up the line before it is emmited
  String tidyLine(String line);
}
