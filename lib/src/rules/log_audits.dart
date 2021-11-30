export '../log_scanner/log_sources/docker_log_source.dart';
export '../log_scanner/log_sources/file_log_source.dart';
export '../log_scanner/log_sources/njcontact_log_source.dart';

import 'package:batman/src/batman_settings.dart';
import 'package:batman/src/rules/batman_yaml_logger.dart';
import 'package:batman/src/rules/rule.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../log_scanner/log_sources/log_source.dart';
import '../log_scanner/log_sources/log_sources.dart';

class LogAudits {
  late final Rules rules;
  List<LogSource> sources = <LogSource>[];

  LogAudits.fromSettings(SettingsYaml settings) {
    rules = Rules.fromMap(settings);

    final location = 'log_audits.log_sources';
    final slist = settings.selectAsList(location);

    if (slist != null) {
      final names = <String>{};
      for (var i = 0; i < slist.length; i++) {
        final source = LogSources.fromMap(settings, '$location.log_source[$i]');
        if (names.isNotEmpty) {
          if (names.contains(source.name)) {
            throw RulesException(
                "You have two log_sources with the same name '${source.name}'");
          }
          names.add(source.name);
        }
        sources.add(source);
      }
    } else {
      BatmanYamlLogger().info(() => 'no log_sources found in rules.yaml');
    }

    // wire logsources to the rules they use.
    _wireSources();
  }

  void _wireSources() {
    for (final source in sources) {
      for (final ref in source.ruleReferences.rules) {
        var rule = _findRule(ref.name);
        if (rule == null) {
          throw RulesException(
              'LogSource: ${source.description} references an unknown rule ${ref.name}');
        }
        ref.rule = rule;
      }
    }
  }

  Rule? _findRule(String name) {
    for (final rule in rules.rules) {
      if (rule.name == name) return rule;
    }
    return null;
  }
}
