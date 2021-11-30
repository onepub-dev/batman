import 'package:batman/src/rules/rule_references.dart';
import 'package:batman/src/settings_yaml_rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../batman_settings.dart';
import '../analysers/source_analyser.dart';

abstract class LogSource {
  /// Controls how many errors from this log source we output
  //late final int top;
  LogSource.fromMap(SettingsYaml settings, String location) {
    top = settings.ruleAsInt(location, 'top', 1000);
    description =
        settings.ruleAsString(location, 'description', 'not supplied');

    name = settings.ruleAsString(location, 'name', '').trim();
    if (name.contains(' ')) {
      throw RulesException(
          'The log_source name "$name" may not contains spaces.');
    }

    

    ruleReferences = RuleReferences.fromMap(settings, location);
  }

  LogSource.virtual(
      {this.top = 1000,
      required this.name,
      this.description = '',
      required this.ruleReferences,
      });

  /// Controls how many events are reported from this log source.
  late final int top;
  late final String description;
  late final String name;

  late final RuleReferences ruleReferences;


  /// Returns true if the log source exists.
  bool get exists;

  SourceAnalyser get analyser;

  // Provides a description of the underlying system resource (e.g. the logfile name)
  // that this source reads logs from.
  String get source;

// Allows the user to over-ride the source by passing in the
// path to an alternate source file
  set overrideSource(String path);

  String getType();

  Stream<String> stream();

  /// Allows the [LogSource] to pre-process the line before
  /// it is passed to the matching engine.
  String preProcessLine(String line);

  /// Allows the source to tidy up the line before it is emmited
  String tidyLine(String line);
}
