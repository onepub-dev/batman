/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:settings_yaml/settings_yaml.dart';

import '../batman_settings.dart';
import '../log_scanner/log_sources/log_source.dart';
import '../log_scanner/log_sources/log_sources.dart';
import 'batman_yaml_logger.dart';
import 'rule.dart';
import 'rules.dart';

export '../log_scanner/log_sources/docker_log_source.dart';
export '../log_scanner/log_sources/file_log_source.dart';
export '../log_scanner/log_sources/njcontact_log_source.dart';

class LogAudits {
  LogAudits.fromSettings(SettingsYaml settings) {
    rules = Rules.fromMap(settings);

    const location = 'log_audits.log_sources';
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
      BatmanYamlLogger().info(() => 'no log_sources found in batman.yaml');
    }

    // wire logsources to the rules they use.
    _wireSources();
  }
  late final Rules rules;
  List<LogSource> sources = <LogSource>[];

  void _wireSources() {
    for (final source in sources) {
      for (final ref in source.ruleReferences.rules) {
        final rule = _findRule(ref.name);
        if (rule == null) {
          throw RulesException(
              'LogSource: ${source.description} references an unknown '
              'rule ${ref.name}');
        }
        ref.rule = rule;
      }
    }
  }

  Rule? _findRule(String name) {
    for (final rule in rules.rules) {
      if (rule.name == name) {
        return rule;
      }
    }
    return null;
  }
}
