/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:dcli/docker.dart';
import 'package:path/path.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:yaml/yaml.dart';

import 'log.dart';

class LocalSettings {
  factory LocalSettings.load() {
    late final SettingsYaml settings;
    late final bool hasLocalSettings;
    final pathToLocalSettings =
        join(DartScript.self.pathToScriptDirectory, filename);
    if (env['RULE_PATH'] != null) {
      settings = SettingsYaml.fromString(content: '''
rule_path: "${env['RULE_PATH']}"
''', filePath: 'settings.yaml');
      hasLocalSettings = true;
    } else if (exists(pathToLocalSettings)) {
      try {
        settings = SettingsYaml.load(pathToSettings: pathToLocalSettings);
        hasLocalSettings = true;
      } on YamlException catch (e) {
        logerr(red('Failed to load rules from $pathToLocalSettings'));
        logerr(red(e.toString()));
        rethrow;
      } on SettingsYamlException catch (e) {
        logerr(red('Failed to load rules from $pathToLocalSettings'));
        logerr(red(e.message));
        rethrow;
      }
    } else {
      settings =
          SettingsYaml.fromString(content: '', filePath: 'settings.yaml');
      hasLocalSettings = false;
    }
    return LocalSettings._internal(
        hasLocalSettings: hasLocalSettings,
        settings: settings,
        pathToLocalSettings: pathToLocalSettings);
  }

  LocalSettings._internal(
      {required this.hasLocalSettings,
      required this.settings,
      required this.pathToLocalSettings});

  SettingsYaml settings;
  bool hasLocalSettings = false;

  static const String filename = 'settings.yaml';

  String pathToLocalSettings;

  String? _rulePath;

  /// Path to the batman.yaml file.
  String get rulePath => _rulePath ?? _pathToRuleYaml;

  set rulePath(String rulePath) {
    settings['rule_path'] = rulePath;

    _rulePath = rulePath;
  }

  String get _pathToRuleYaml {
    late final String path;

    if (hasLocalSettings) {
      final rulePath = settings.asString('rule_path');
      if (rulePath.isEmpty) {
        throw SettingsYamlException(
            'settings.yaml found in $pathToLocalSettings '
            'but a value for the expected rule_path key was not found');
      }
      path = rulePath;
    } else {
      path = join(HOME, '.batman', 'batman.yaml');
    }
    return truepath(path);
  }

  Future<void> save() async {
    await settings.save();
  }

  /// name of the package batman.yaml file appropriate for the target platform.
  String get packedRuleYaml {
    late final String path;
    if (DockerShell.inDocker) {
      path = 'batman_docker.yaml';
    } else {
      path = 'batman_local.yaml';
    }
    return path;
  }
}
